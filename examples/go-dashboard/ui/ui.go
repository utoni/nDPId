package ui

import (
	"context"
	"time"

	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/keyboard"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/termbox"
	"github.com/mum4k/termdash/terminal/terminalapi"
	"github.com/mum4k/termdash/widgets/text"
)

const rootID = "root"
const redrawInterval = 250 * time.Millisecond

type widgets struct {
	menu *text.Text
}

func newWidgets(ctx context.Context) (*widgets, error) {
	menu, err := text.New(text.RollContent(), text.WrapAtWords())
	if err != nil {
		panic(err)
	}

	return &widgets{
		menu: menu,
	}, nil
}

func Init() {
	term, err := termbox.New(termbox.ColorMode(terminalapi.ColorMode256))

	if err != nil {
		panic(err)
	}
	defer term.Close()

	ctx, cancel := context.WithCancel(context.Background())
	wdgts, err := newWidgets(ctx)
	if err != nil {
		panic(err)
	}

	cnt, err := container.New(term,
		container.Border(linestyle.None),
		container.BorderTitle("[ESC to Quit]"),
		container.SplitHorizontal(
			container.Top(
				container.Border(linestyle.Light),
				container.BorderTitle("Go nDPId Dashboard"),
				container.PlaceWidget(wdgts.menu),
			),
			container.Bottom(
				container.Border(linestyle.Light),
				container.BorderTitle("Raw JSON"),
				container.PlaceWidget(wdgts.menu),
			),
			container.SplitFixed(3),
		),
	)
	if err != nil {
		panic(err)
	}

	quitter := func(k *terminalapi.Keyboard) {
		if k.Key == keyboard.KeyEsc || k.Key == keyboard.KeyCtrlC {
			cancel()
		}
	}
	if err := termdash.Run(ctx, term, cnt, termdash.KeyboardSubscriber(quitter), termdash.RedrawInterval(redrawInterval)); err != nil {
		panic(err)
	}
}
