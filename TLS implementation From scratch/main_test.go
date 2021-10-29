package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTlsServer(t *testing.T) {

	serverBinary := "testingExamples.exe"
	cmd := exec.Command(serverBinary)
	if cmd.Start() != nil {
		log.Println("Server failed to start ...")
		t.Fatal()
	}
	defer cmd.Process.Kill()
	log.Println("server started... ")
	url := "https://127.0.0.1:8080/"
	result := "Hello, world!"
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	response, err := client.Get(url)
	if err != nil {
		log.Fatalf(err.Error())
		return
	}
	defer response.Body.Close()

	content, _ := ioutil.ReadAll(response.Body)

	if err != nil {
		t.Fatalf("Failed in reading response ")
	}

	log.Println("Response: ", string(content))
	assert.Equal(t, string(content), result)
}
