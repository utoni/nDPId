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

type Tui struct {
	Term       terminalapi.Terminal
	Context    context.Context
	Cancel     context.CancelFunc
	Container  *container.Container
	MainTicker *time.Ticker
}

type Widgets struct {
	Menu    *text.Text
	RawJson *text.Text
}

func newWidgets(ctx context.Context) (*Widgets, error) {
	menu, err := text.New()
	if err != nil {
		panic(err)
	}

	rawJson, err := text.New(text.RollContent(), text.WrapAtWords())
	if err != nil {
		panic(err)
	}

	return &Widgets{
		Menu:    menu,
		RawJson: rawJson,
	}, nil
}

func Init() (*Tui, *Widgets) {
	var err error

	ui := Tui{}

	ui.Term, err = termbox.New(termbox.ColorMode(terminalapi.ColorMode256))
	if err != nil {
		panic(err)
	}

	ui.Context, ui.Cancel = context.WithCancel(context.Background())

	wdgts, err := newWidgets(ui.Context)
	if err != nil {
		panic(err)
	}

	ui.Container, err = container.New(ui.Term,
		container.Border(linestyle.None),
		container.BorderTitle("[ESC to Quit]"),
		container.SplitHorizontal(
			container.Top(
				container.Border(linestyle.Light),
				container.BorderTitle("Go nDPId Dashboard"),
				container.PlaceWidget(wdgts.Menu),
			),
			container.Bottom(
				container.Border(linestyle.Light),
				container.BorderTitle("Raw JSON"),
				container.PlaceWidget(wdgts.RawJson),
			),
			container.SplitFixed(3),
		),
	)
	if err != nil {
		panic(err)
	}

	ui.MainTicker = time.NewTicker(1 * time.Second)

	return &ui, wdgts
}

func Run(ui *Tui) {
	defer ui.Term.Close()

	quitter := func(k *terminalapi.Keyboard) {
		if k.Key == keyboard.KeyEsc || k.Key == keyboard.KeyCtrlC {
			ui.Cancel()
		}
	}

	if err := termdash.Run(ui.Context, ui.Term, ui.Container, termdash.KeyboardSubscriber(quitter), termdash.RedrawInterval(redrawInterval)); err != nil {
		panic(err)
	}
}
