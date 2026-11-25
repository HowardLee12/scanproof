package exception

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

const nullTag = "!!null"

// checkStructure refuses what lets an exceptions file mean something other
// than what each entry shows: YAML anchors, aliases and merge keys, which
// bring in keys and values from elsewhere, and "artifact:" without a value,
// which YAML decodes as if the key were missing. Either could widen an
// exception to every artifact without anyone reading it that way.
func checkStructure(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil // the decoder reports syntax errors
	}
	if err := refuseIndirection(&doc); err != nil {
		return err
	}
	return refuseNullArtifacts(&doc)
}

// refuseIndirection walks every node, keys included.
func refuseIndirection(node *yaml.Node) error {
	switch {
	case node.Kind == yaml.AliasNode:
		return fmt.Errorf("line %d: YAML aliases (*%s) are not supported in an exceptions file; write the value out",
			node.Line, node.Value)
	case node.Anchor != "":
		return fmt.Errorf("line %d: YAML anchors (&%s) are not supported in an exceptions file; write the value out",
			node.Line, node.Anchor)
	case node.Kind == yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			if key := node.Content[i]; key.Value == "<<" {
				return fmt.Errorf("line %d: merge keys (<<) are not supported in an exceptions file; write the fields out", key.Line)
			}
		}
	}
	for _, child := range node.Content {
		if err := refuseIndirection(child); err != nil {
			return err
		}
	}
	return nil
}

// refuseNullArtifacts refuses "artifact:" with no value (or null, ~).
// Without aliases and merge keys, every exception is a literal entry of
// the top-level exceptions list.
func refuseNullArtifacts(doc *yaml.Node) error {
	if len(doc.Content) == 0 {
		return nil
	}
	list := mappingValue(doc.Content[0], "exceptions")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	for i, item := range list.Content {
		v := mappingValue(item, "artifact")
		if v == nil || v.Tag != nullTag {
			continue
		}
		where := fmt.Sprintf("exception %d", i+1)
		if id := mappingValue(item, "id"); id != nil && id.Value != "" {
			where = "exception " + id.Value
		}
		return fmt.Errorf("%s: artifact has no value; leave it out to apply the exception to every image and directory", where)
	}
	return nil
}

// mappingValue returns the value of key in a YAML mapping, or nil.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
