package console

import "testing"

func TestContextStack_PushPopNavigation(t *testing.T) {
	root := ConsoleContext{Type: Workspace, ID: "ws1", Label: "metasploitable3"}
	stack := NewContextStack(root)

	if got := stack.Current(); got != root {
		t.Fatalf("Current() inicial = %+v, want %+v", got, root)
	}

	host := ConsoleContext{Type: Host, ID: "192.168.72.130", Label: "192.168.72.130"}
	stack.Push(host)
	if got := stack.Current(); got != host {
		t.Fatalf("Current() tras push host = %+v, want %+v", got, host)
	}

	svc := ConsoleContext{Type: Service, ID: "svc1", Label: "445/smb"}
	stack.Push(svc)
	if got := stack.Current(); got != svc {
		t.Fatalf("Current() tras push service = %+v, want %+v", got, svc)
	}

	back1, ok := stack.Pop()
	if !ok {
		t.Fatal("Pop() desde service devolvió ok=false, want true")
	}
	if back1 != host {
		t.Errorf("Pop() desde service = %+v, want volver a %+v", back1, host)
	}

	back2, ok := stack.Pop()
	if !ok {
		t.Fatal("Pop() desde host devolvió ok=false, want true")
	}
	if back2 != root {
		t.Errorf("Pop() desde host = %+v, want volver a %+v", back2, root)
	}
}

func TestContextStack_PopAtRootNeverErrors(t *testing.T) {
	root := ConsoleContext{Type: Workspace, ID: "ws1", Label: "metasploitable3"}
	stack := NewContextStack(root)

	got, ok := stack.Pop()
	if ok {
		t.Error("Pop() en la raíz devolvió ok=true, want false")
	}
	if got != root {
		t.Errorf("Pop() en la raíz devolvió %+v, want el propio root %+v (sin romper nada)", got, root)
	}
	if stack.Depth() != 1 {
		t.Errorf("Depth() tras Pop() en la raíz = %d, want 1 (no debe vaciarse)", stack.Depth())
	}
}

func TestContextStack_ResetToRootReplacesEntireBase(t *testing.T) {
	stack := NewContextStack(ConsoleContext{Type: Workspace, ID: "ws1", Label: "A"})
	stack.Push(ConsoleContext{Type: Host, ID: "10.0.0.1"})
	stack.Push(ConsoleContext{Type: Service, ID: "svc1"})

	newRoot := ConsoleContext{Type: Workspace, ID: "ws2", Label: "B"}
	stack.ResetToRoot(newRoot)

	if stack.Depth() != 1 {
		t.Errorf("Depth() tras ResetToRoot = %d, want 1 (host/service anteriores deben descartarse)", stack.Depth())
	}
	if got := stack.Current(); got != newRoot {
		t.Errorf("Current() tras ResetToRoot = %+v, want %+v", got, newRoot)
	}
	// Un Pop() inmediatamente después debe comportarse como si siempre
	// hubiera estado en la raíz del workspace nuevo.
	if _, ok := stack.Pop(); ok {
		t.Error("Pop() justo tras ResetToRoot devolvió ok=true, want false (ya es la raíz del nuevo workspace)")
	}
}
