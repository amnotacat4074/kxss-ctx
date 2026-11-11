package main

// Dependency-free HTML scanner.
//
// It answers one question: "what syntactic context does byte N of this
// document sit in?" That context is the thing kxss is missing. A quote in a
// JSON string is inert; the same quote inside a double-quoted attribute is an
// injection. Same byte, different verdict.
//
// A hand-rolled scanner (rather than encoding/xml or x/net/html) is used
// because we need byte offsets, and the standard tokenizers do not expose
// them or the original attribute quoting style.

type Kind int

const (
	KindText Kind = iota
	KindTag
	KindAttrDQ
	KindAttrSQ
	KindAttrUQ
	KindComment
	KindScriptRaw
	KindScriptDQ
	KindScriptSQ
	KindScriptTemplate
	KindStyle
	KindRcdata
)

func (k Kind) String() string {
	switch k {
	case KindText:
		return "html-text"
	case KindTag:
		return "tag"
	case KindAttrDQ:
		return "attr-double-quoted"
	case KindAttrSQ:
		return "attr-single-quoted"
	case KindAttrUQ:
		return "attr-unquoted"
	case KindComment:
		return "html-comment"
	case KindScriptRaw:
		return "script-code"
	case KindScriptDQ:
		return "script-double-quoted"
	case KindScriptSQ:
		return "script-single-quoted"
	case KindScriptTemplate:
		return "script-template-literal"
	case KindStyle:
		return "style"
	case KindRcdata:
		return "rcdata"
	}
	return "unknown"
}

// Context describes where a reflection landed.
type Context struct {
	Kind       Kind
	Tag        string // element the reflection is inside, if any
	Attr       string // attribute name, if the reflection is in one
	ScriptType string // value of the <script type="..."> attribute
	ValueStart int    // byte offset where the attribute value begins
}

type scanState int

const (
	stateData scanState = iota
	stateLt
	stateEndTag
	stateTagName
	stateBeforeAttr
	stateAttrName
	stateAfterAttrName
	stateBeforeValue
	stateValueDQ
	stateValueSQ
	stateValueUQ
	stateComment
	stateScript
	stateStyle
	stateRcdata
)

type jsState int

const (
	jsNone jsState = iota
	jsSingle
	jsDouble
	jsTemplate
)

type scanner struct {
	src []byte
	i   int
	st  scanState

	tag        string
	attr       string
	attrBuf    []byte
	scriptType string

	valueStart int
	js         jsState
}

// classifyAt returns the context of src[idx].
func classifyAt(src []byte, idx int) Context {
	s := &scanner{src: src}
	s.run(idx)
	return s.context()
}

func (s *scanner) run(limit int) {
	if limit > len(s.src) {
		limit = len(s.src)
	}
	for s.i < limit {
		c := s.src[s.i]
		switch s.st {
		case stateData:
			if c == '<' {
				s.st = stateLt
			}
			s.i++

		case stateLt:
			switch {
			case c == '!':
				s.st = stateComment
				s.i++
			case c == '/':
				s.st = stateEndTag
				s.i++
			case isAlpha(c):
				s.st = stateTagName
				s.tag = string(lower(c))
				s.attr = ""
				s.scriptType = ""
				s.i++
			default:
				s.st = stateData
				s.i++
			}

		case stateEndTag:
			if c == '>' {
				s.st = stateData
				s.tag = ""
				s.attr = ""
				s.scriptType = ""
			}
			s.i++

		case stateTagName:
			switch {
			case isSpace(c):
				s.st = stateBeforeAttr
				s.i++
			case c == '>':
				s.i++
				s.closeTag()
			case c == '/':
				s.st = stateBeforeAttr
				s.i++
			default:
				s.tag += string(lower(c))
				s.i++
			}

		case stateBeforeAttr:
			switch {
			case isSpace(c):
				s.i++
			case c == '>':
				s.i++
				s.closeTag()
			case c == '/':
				s.i++
			default:
				s.st = stateAttrName
				s.attrBuf = s.attrBuf[:0]
				s.attrBuf = append(s.attrBuf, lower(c))
				s.i++
			}

		case stateAttrName:
			switch {
			case isSpace(c):
				s.attr = string(s.attrBuf)
				s.st = stateAfterAttrName
				s.i++
			case c == '=':
				s.attr = string(s.attrBuf)
				s.st = stateBeforeValue
				s.i++
			case c == '>':
				s.attr = string(s.attrBuf)
				s.i++
				s.closeTag()
			case c == '/':
				s.attr = string(s.attrBuf)
				s.st = stateBeforeAttr
				s.i++
			default:
				s.attrBuf = append(s.attrBuf, lower(c))
				s.i++
			}

		case stateAfterAttrName:
			switch {
			case isSpace(c):
				s.i++
			case c == '=':
				s.st = stateBeforeValue
				s.i++
			case c == '>':
				s.i++
				s.closeTag()
			default:
				s.st = stateAttrName
				s.attrBuf = s.attrBuf[:0]
				s.attrBuf = append(s.attrBuf, lower(c))
				s.i++
			}

		case stateBeforeValue:
			switch {
			case isSpace(c):
				s.i++
			case c == '"':
				s.st = stateValueDQ
				s.valueStart = s.i + 1
				s.i++
			case c == '\'':
				s.st = stateValueSQ
				s.valueStart = s.i + 1
				s.i++
			case c == '>':
				s.i++
				s.closeTag()
			default:
				s.st = stateValueUQ
				s.valueStart = s.i
			}

		case stateValueDQ:
			if c == '"' {
				s.endValue(s.i)
				s.st = stateBeforeAttr
			}
			s.i++

		case stateValueSQ:
			if c == '\'' {
				s.endValue(s.i)
				s.st = stateBeforeAttr
			}
			s.i++

		case stateValueUQ:
			switch {
			case isSpace(c):
				s.endValue(s.i)
				s.st = stateBeforeAttr
				s.i++
			case c == '>':
				s.endValue(s.i)
				s.i++
				s.closeTag()
			default:
				s.i++
			}

		case stateComment:
			if c == '-' && s.hasPrefix("-->") {
				s.st = stateData
				s.i += 3
				continue
			}
			if c == '>' {
				s.st = stateData
			}
			s.i++

		case stateScript:
			if s.js == jsNone {
				if c == '<' && s.hasPrefixFold("</script") {
					s.st = stateEndTag
					s.tag = ""
					s.i++
					continue
				}
				switch c {
				case '\'':
					s.js = jsSingle
				case '"':
					s.js = jsDouble
				case '`':
					s.js = jsTemplate
				}
				s.i++
				continue
			}
			if c == '\\' {
				s.i += 2
				continue
			}
			switch s.js {
			case jsSingle:
				if c == '\'' {
					s.js = jsNone
				}
			case jsDouble:
				if c == '"' {
					s.js = jsNone
				}
			case jsTemplate:
				if c == '`' {
					s.js = jsNone
				}
			}
			s.i++

		case stateStyle:
			if c == '<' && s.hasPrefixFold("</style") {
				s.st = stateEndTag
				s.tag = ""
				s.i++
				continue
			}
			s.i++

		case stateRcdata:
			if c == '<' && (s.hasPrefixFold("</textarea") || s.hasPrefixFold("</title")) {
				s.st = stateEndTag
				s.tag = ""
				s.i++
				continue
			}
			s.i++
		}
	}
}

func (s *scanner) endValue(end int) {
	if s.attr == "type" {
		s.scriptType = lowerString(string(s.src[s.valueStart:end]))
	}
}

func (s *scanner) closeTag() {
	switch s.tag {
	case "script":
		s.st = stateScript
		s.js = jsNone
	case "style":
		s.st = stateStyle
	case "textarea", "title":
		s.st = stateRcdata
	default:
		s.st = stateData
		s.scriptType = ""
	}
	s.attr = ""
}

func (s *scanner) context() Context {
	c := Context{Tag: s.tag, Attr: s.attr, ScriptType: s.scriptType, ValueStart: s.valueStart}
	switch s.st {
	case stateValueDQ:
		c.Kind = KindAttrDQ
	case stateValueSQ:
		c.Kind = KindAttrSQ
	case stateValueUQ:
		c.Kind = KindAttrUQ
	case stateComment:
		c.Kind = KindComment
	case stateScript:
		switch s.js {
		case jsSingle:
			c.Kind = KindScriptSQ
		case jsDouble:
			c.Kind = KindScriptDQ
		case jsTemplate:
			c.Kind = KindScriptTemplate
		default:
			c.Kind = KindScriptRaw
		}
	case stateStyle:
		c.Kind = KindStyle
	case stateRcdata:
		c.Kind = KindRcdata
	case stateData:
		c.Kind = KindText
	default:
		c.Kind = KindTag
	}
	return c
}

func (s *scanner) hasPrefix(p string) bool {
	if s.i+len(p) > len(s.src) {
		return false
	}
	for j := 0; j < len(p); j++ {
		if s.src[s.i+j] != p[j] {
			return false
		}
	}
	return true
}

func (s *scanner) hasPrefixFold(p string) bool {
	if s.i+len(p) > len(s.src) {
		return false
	}
	for j := 0; j < len(p); j++ {
		if lower(s.src[s.i+j]) != lower(p[j]) {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

func lowerString(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = lower(b[i])
	}
	return string(b)
}
