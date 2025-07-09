package cli

import (
	"io"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

func newTable(header []string, data [][]string, w io.Writer) *tablewriter.Table {
	table := tablewriter.NewTable(w,
		tablewriter.WithRenderer(renderer.NewBlueprint(
			tw.Rendition{
				Borders: tw.BorderNone,
				Symbols: tw.NewSymbols(tw.StyleASCII),
				Settings: tw.Settings{
					Lines: tw.Lines{
						ShowHeaderLine: tw.Off,
						ShowFooterLine: tw.Off,
						ShowTop:        tw.Off,
						ShowBottom:     tw.Off,
					},
					Separators: tw.Separators{
						ShowHeader:     tw.Off,
						ShowFooter:     tw.Off,
						BetweenRows:    tw.Off,
						BetweenColumns: tw.Off,
					},
				},
			},
		)),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignLeft},
			},
			Row: tw.CellConfig{
				Formatting:   tw.CellFormatting{AutoWrap: tw.WrapNone},
				Alignment:    tw.CellAlignment{Global: tw.AlignLeft},
				ColMaxWidths: tw.CellWidth{Global: 50},
			},
		}),
	)

	table.Header(header)
	table.Bulk(data)

	return table
}
