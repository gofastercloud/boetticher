package controllerstatus

// Debouncer requires two consecutive failures before showing red and one
// success to recover. The first failed observation remains blue/checking.
type Debouncer struct {
	state    State
	failures int
}

func NewDebouncer(initial State) *Debouncer {
	return &Debouncer{state: initial}
}

func (d *Debouncer) Update(ok bool, detail string) Component {
	if ok {
		d.failures = 0
		d.state = Healthy
		return Component{State: d.state, Detail: detail}
	}
	d.failures++
	if d.failures >= 2 {
		d.state = Failed
	} else if d.state != Failed {
		d.state = Checking
	}
	return Component{State: d.state, Detail: detail}
}
