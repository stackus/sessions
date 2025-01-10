package sessions

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFlash_Add(t *testing.T) {
	// Arrange
	f := Flash{}
	key := "key"
	message := "message"

	// Act
	f.Add(key, message)

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Add() = %v, want %v", got, message)
	}
}

func TestFlash_AddReread(t *testing.T) {
	// Arrange
	f := Flash{}
	key := "key"
	message := "message"

	// Act
	f.Add(key, message)

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Add() = %v, want %v", got, message)
	}
	if got := f.Get(key); got != "" {
		t.Errorf("Flash.Add() = %v, want %v", got, "")
	}
}

func TestFlash_AddNextRequest(t *testing.T) {
	// Arrange
	f := &Flash{} // use a pointer to test JSON serialization; when Flash is a field in a struct, it does not need to be a pointer
	key := "key"
	message := "message"

	// Act
	f.Add(key, message)
	times := 0
	for {
		if times == 1 {
			break
		}
		times++
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(f); err != nil {
			t.Fatal(err)
		}
		f.Clear()
		if err := json.NewDecoder(&buf).Decode(&f); err != nil {
			t.Fatal(err)
		}
	}

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Add() = %v, want %v", got, message)
	}
}

func TestFlash_AddNextTwoRequests(t *testing.T) {
	// Arrange
	f := &Flash{} // use a pointer to test JSON serialization; when Flash is a field in a struct, it does not need to be a pointer
	key := "key"
	message := "message"

	// Act
	f.Add(key, message)
	times := 0
	for {
		if times == 2 {
			break
		}
		times++
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(f); err != nil {
			t.Fatal(err)
		}
		f.Clear()
		if err := json.NewDecoder(&buf).Decode(&f); err != nil {
			t.Fatal(err)
		}
	}

	// Assert
	if got := f.Get(key); got != "" {
		t.Errorf("Flash.Add() = %v, want %v", got, "")
	}
}

func TestFlash_Now(t *testing.T) {
	// Arrange
	f := Flash{}
	key := "key"
	message := "message"

	// Act
	f.Now(key, message)

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Now() = %v, want %v", got, message)
	}
}

func TestFlash_NowReread(t *testing.T) {
	// Arrange
	f := Flash{}
	key := "key"
	message := "message"

	// Act
	f.Now(key, message)

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Now() = %v, want %v", got, message)
	}
	if got := f.Get(key); got != "" {
		t.Errorf("Flash.Now() = %v, want %v", got, "")
	}
}

func TestFlash_NowNextRequest(t *testing.T) {
	// Arrange
	f := &Flash{} // use a pointer to test JSON serialization; when Flash is a field in a struct, it does not need to be a pointer
	key := "key"
	message := "message"

	// Act
	f.Now(key, message)
	times := 0
	for {
		if times == 1 {
			break
		}
		times++
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(f); err != nil {
			t.Fatal(err)
		}
		f.Clear()
		if err := json.NewDecoder(&buf).Decode(&f); err != nil {
			t.Fatal(err)
		}
	}

	// Assert
	if got := f.Get(key); got != "" {
		t.Errorf("Flash.Now() = %v, want %v", got, "")
	}
}

func TestFlash_Keep(t *testing.T) {
	// Arrange
	f := Flash{}
	key := "key"
	message := "message"

	// Act
	f.Keep(key, message)

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Keep() = %v, want %v", got, message)
	}
}

func TestFlash_KeepReread(t *testing.T) {
	// Arrange
	f := Flash{}
	key := "key"
	message := "message"

	// Act
	f.Keep(key, message)

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Keep() = %v, want %v", got, message)
	}
	if got := f.Get(key); got != "" {
		t.Errorf("Flash.Keep() = %v, want %v", got, "")
	}
}

func TestFlash_KeepNextRequest(t *testing.T) {
	// Arrange
	f := &Flash{} // use a pointer to test JSON serialization; when Flash is a field in a struct, it does not need to be a pointer
	key := "key"
	message := "message"

	// Act
	f.Keep(key, message)
	times := 0
	for {
		if times == 1 {
			break
		}
		times++
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(f); err != nil {
			t.Fatal(err)
		}
		f.Clear()
		if err := json.NewDecoder(&buf).Decode(&f); err != nil {
			t.Fatal(err)
		}
	}

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Keep() = %v, want %v", got, message)
	}
}

func TestFlash_KeepNextTwoRequests(t *testing.T) {
	// Arrange
	f := &Flash{} // use a pointer to test JSON serialization; when Flash is a field in a struct, it does not need to be a pointer
	key := "key"
	message := "message"

	// Act
	f.Keep(key, message)
	times := 0
	for {
		if times == 2 {
			break
		}
		times++
		buf := bytes.Buffer{}
		if err := json.NewEncoder(&buf).Encode(f); err != nil {
			t.Fatal(err)
		}
		f.Clear()
		if err := json.NewDecoder(&buf).Decode(&f); err != nil {
			t.Fatal(err)
		}
	}

	// Assert
	if got := f.Get(key); got != message {
		t.Errorf("Flash.Keep() = %v, want %v", got, message)
	}
}
