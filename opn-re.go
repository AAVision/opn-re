package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gookit/color"
	"golang.org/x/exp/slices"
)

func starter(UserInput UserInput) error {
	/**
	This method is the starter of the package.
	@var UserInput UserInput.
	@return error.
	*/

	var testingUrls []string
	var modifiedUrls []string

	if (UserInput.Domain == "" && UserInput.Input == "") || (UserInput.Domain != "" && UserInput.Input != "") {
		return errors.New("please add a domain or input file with domains")
	}

	if UserInput.Input == "" {

		if UserInput.Domain == "" {
			return errors.New("please add a valid domain name")
		}

		if !UserInput.Simple {
			webArchiveUrls := getWebArchiveUrls(UserInput.Domain)

			testingUrls = getTestingUrl(webArchiveUrls)

			if !UserInput.Force {
				keys := readFile("config.txt")
				testingUrls = filterUrls(testingUrls, keys)
			}

			modifiedUrls = replaceUrls(testingUrls, UserInput.Xss)

			color.Greenln("Number of links to be scanned:", len(modifiedUrls))

		} else {
			keys := readFile("config.txt")
			modifiedUrls = alterUrl(UserInput.Domain, keys)
		}

	} else {
		keys := readFile("config.txt")
		domains := readFile(UserInput.Input)
		modifiedUrls = alterUrl(domains, keys)
	}

	result, err := callUrls(modifiedUrls, UserInput.Xss)

	if err != nil {
		log.Fatal(err)
	}

	if len(result) == 0 {
		color.Redln("No vulnerable urls were detected!")
	} else {
		color.Greenln("The vulnerable urls are: ", result)
	}

	return nil
}

func getWebArchiveUrls(domain string) []string {
	/**
	This method will get all the archived urls of the domain.
	@var domain string.
	@return []string.
	*/
	var webArchiveUrls [][]string
	var results []string

	spinner := spinnerStarter(9, "yellow", " Getting archives... ")

	client := &http.Client{}

	url := "https://web.archive.org/cdx/search/cdx?url=*." + domain + "&output=json&fl=original&collapse=urlkey"
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Add("User-Agent", getUserAgents())
	resp, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Fatalln(err)
	}

	err = json.Unmarshal([]byte(body), &webArchiveUrls)

	if err != nil {
		log.Fatalln("No Data Found!")
	}

	spinnerStopper(spinner)
	color.Greenln("✔️")

	createFile("archive_"+domain+"_"+getRandomString(5)+".txt", string(body))

	for _, a := range webArchiveUrls {
		results = append(results, a...)
	}

	return results

}

func getTestingUrl(webArchiveUrls []string) []string {
	/**
	This method will get all the testing urls that contains ? and =.
	@var webArchiveUrls [][]string.
	@return []string.
	*/
	var testingUrls []string

	for _, url := range webArchiveUrls {
		if strings.Contains(url, "?") && strings.Contains(url, "=") {
			testingUrls = append(testingUrls, url)
		}
	}

	return testingUrls
}

func filterUrls(urls []string, keys []string) []string {
	/**
	This method will search for the url based on a provided keys.
	@var testingUrls []string.
	@return []string.
	*/
	var filteredUrls []string

	for _, url := range urls {
		queryParams := strings.Split(url, "?")[1]
		parameters := strings.Split(queryParams, "&")

		for _, parameter := range parameters {
			paraIndex := strings.Split(parameter, "=")
			if slices.Contains(keys, paraIndex[0]) {
				filteredUrls = append(filteredUrls, url)
			}
		}
	}

	return filteredUrls
}

func replaceUrls(testingUrls []string, isXss bool) []string {
	/**
	This method will replace querystring with open redirect payload.
	@var testingUrls []string.
	@return []string.
	*/
	var modifiedUrls []string
	var paramCheck string
	payloads := readFile("open-redirect-payloads.txt")

	for _, url := range testingUrls {
		queryParams := strings.Split(url, "?")[1]
		parameters := strings.Split(queryParams, "&")

		for _, parameter := range parameters {
			paraIndex := strings.Split(parameter, "=")
			if len(paraIndex) > 1 {
				paraString := paraIndex[0] + "=" + paraIndex[1]
				if !isXss {
					for _, payload := range payloads {
						paramCheck = paraIndex[0] + "=" + strings.Replace(paraIndex[1], paraIndex[1], string(payload), 1)
					}
				} else {
					paramCheck = paraIndex[0] + "=" + strings.Replace(paraIndex[1], paraIndex[1], "jUbAeR", 1)
				}

				modifiedUrls = append(modifiedUrls, strings.Replace(url, paraString, paramCheck, 1))
			}
		}
	}

	return modifiedUrls
}

func checkRedirects(url string, ch chan<- string, wg *sync.WaitGroup) {
	/**
	This method will call modified urls async in channels and check for 302 redirect.
	@var url string.
	@var ch chan of boolean.
	@var wg WaitGroup.
	@return nil.
	*/
	defer wg.Done()

	color.Grayln("Scanning:", url)

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		ch <- ""
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()
	req = req.WithContext(ctx)

	client := new(http.Client)

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		ch <- url
		return nil
	}

	response, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
		ch <- ""
		return
	}

	defer response.Body.Close()

}

func callUrls(modifiedUrls []string, isXss bool) ([]string, error) {
	/**
	This method will call all URLs.
	@var modifiedUrls []string.
	@return []bool and error.
	*/
	ch := make(chan string)
	var responses []string

	var modifiedUrl string

	var wg sync.WaitGroup

	for _, modifiedUrl = range modifiedUrls {
		wg.Add(1)
		if !isXss {
			go checkRedirects(modifiedUrl, ch, &wg)
		} else {
			go checkXss(modifiedUrl, ch, &wg)
		}

	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for res := range ch {
		if res != "" {
			responses = append(responses, res)
		}
	}

	return responses, nil
}

func checkXss(url string, ch chan<- string, wg *sync.WaitGroup) {
	/**
	This method will check if the url is vulernable to XSS.
	@var url string.
	@var ch chan<- string.
	@var wg WaitGroup.
	@return nil.
	*/
	defer wg.Done()

	color.Grayln("Scanning:", url)

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		ch <- ""
		return
	}

	req.Header.Add("User-Agent", getUserAgents())
	resp, err := client.Do(req)

	if err != nil {
		ch <- ""
		return
	}

	body, err := io.ReadAll(resp.Body)

	defer resp.Body.Close()

	if err != nil {
		ch <- ""
		return
	}

	found, err := regexp.MatchString("jUbAeR", string(body))

	if err != nil {
		ch <- ""
		return
	}

	if found {
		ch <- url
	}

	ch <- ""
	return

}

func alterUrl(url interface{}, keys []string) []string {
	/**
	This method will alter a single or multiple URL.
	@var url string or []string.
	@var keys []string.
	@return []string.
	*/
	var testingUrls []string
	v := reflect.ValueOf(url)

	switch v.Kind() {
	case reflect.String:
		for _, key := range keys {
			testingUrls = append(testingUrls, "http://"+url.(string)+"?"+key+"="+"https://www.google.com/")
		}
	case reflect.Slice:
		for _, _url := range url.([]string) {
			for _, key := range keys {
				testingUrls = append(testingUrls, "http://"+_url+"?"+key+"="+"https://www.google.com/")
			}
		}
	}

	return testingUrls
}
