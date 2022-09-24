package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	twitter "github.com/g8rswimmer/go-twitter/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type authorize struct {
	Token string
}

type twitterToken struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func (a authorize) Add(req *http.Request) {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", a.Token))
}

func main() {
	ctx := context.Background()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Trace().Msg("Starting...")

	tok := getToken()
	c := getClient(tok.AccessToken)

	// GET CURRENT USER
	ulo := twitter.UserLookupOpts{
		UserFields: []twitter.UserField{
			twitter.UserFieldCreatedAt,
			twitter.UserFieldDescription,
		},
	}
	resp, err := c.AuthUserLookup(ctx, ulo)
	// resp, err := c.UserLookup(ctx, []string{"@praetorian"}, ulo)
	if err != nil {
		log.Error().Err(err).Msg("Unable to lookup authenticated user")
		return
	}
	users := resp.Raw.Users
	if len(users) != 1 {
		log.Fatal().Int("users", len(users)).Msg("Expected 1 user")
	}
	currentUser := users[0]
	fmt.Println(currentUser)
	log.Trace().Str("id", currentUser.ID).Str("name", currentUser.Name).Str("username", currentUser.UserName).Str("id", currentUser.ID).Msg("Current User")
	waitForRateLimit(resp.RateLimit)

	// GET THE PEOPLE THAT USER FOLLOWS
	uflo := twitter.UserFollowingLookupOpts{
		UserFields: []twitter.UserField{
			twitter.UserFieldCreatedAt,
			twitter.UserFieldDescription,
		},
		MaxResults: 1000, // use a big number here to avoid the rate limits
	}
	allFollowing := make([]*twitter.UserObj, 0)

	for {
		log.Trace().Str("userid", currentUser.ID).Str("pagetoken", uflo.PaginationToken).Msg("Fetching folows")
		followingResp, err := c.UserFollowingLookup(ctx, currentUser.ID, uflo)
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to get following")
		}
		log.Trace().Str("userid", currentUser.ID).Str("pagetoken", uflo.PaginationToken).Msg("Received response")
		waitForRateLimit(followingResp.RateLimit)
		allFollowing = append(allFollowing, followingResp.Raw.Users...)
		uflo.PaginationToken = followingResp.Meta.NextToken
		if followingResp.Meta.NextToken == "" {
			break
		}
	}
	followingJson, err := json.Marshal(allFollowing)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to marshal following slice to json")
	}
	err = os.WriteFile("following.json", followingJson, 0660)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to save following to file")
	}

	// GET THE LISTS THIS USER OWNS
	ullo := twitter.UserListLookupOpts{
		UserFields: []twitter.UserField{
			twitter.UserFieldCreatedAt,
			twitter.UserFieldDescription,
		},
		MaxResults: 100,
	}
	allLists := make([]*twitter.ListObj, 0)
	for {
		log.Trace().Str("userid", currentUser.ID).Str("pagetoken", ullo.PaginationToken).Msg("Fetching list")
		listsResp, err := c.UserListLookup(ctx, currentUser.ID, ullo)
		if err != nil {
			log.Fatal().Err(err).Msg("Unable to get list")
		}
		log.Trace().Str("userid", currentUser.ID).Str("pagetoken", ullo.PaginationToken).Msg("Received Response")
		waitForRateLimit(listsResp.RateLimit)
		allLists = append(allLists, listsResp.Raw.Lists...)
		ullo.PaginationToken = listsResp.Meta.NextToken
		if listsResp.Meta.NextToken == "" {
			break
		}
	}
	listsJson, err := json.Marshal(allLists)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to marshal lists slice to json")
	}
	err = os.WriteFile("lists.json", listsJson, 0660)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to save lists to file")
	}

	// GET THE PEOPLE THAT BELONG TO THOSE LISTS
	lumo := twitter.ListUserMembersOpts{
		UserFields: []twitter.UserField{
			twitter.UserFieldCreatedAt,
			twitter.UserFieldDescription,
		},
		MaxResults: 100,
	}
	allListMembers := make(map[string][]*twitter.UserObj, 0)
	for _, list := range allLists {
		// allListMembers[list.ID] = make([]*twitter.UserObj, 0)
		listMembers := make([]*twitter.UserObj, 0)
		for {
			log.Trace().Str("listid", list.ID).Str("pagetoken", lumo.PaginationToken).Msg("Fetching list user members")
			listMembersResp, err := c.ListUserMembers(ctx, list.ID, lumo)
			if err != nil {
				log.Fatal().Err(err).Msg("Unable to get list members")
			}
			log.Trace().Str("listid", list.ID).Str("pagetoken", lumo.PaginationToken).Msg("Received Response")
			waitForRateLimit(listMembersResp.RateLimit)
			listMembers = append(listMembers, listMembersResp.Raw.Users...)
			lumo.PaginationToken = listMembersResp.Meta.NextToken
			if listMembersResp.Meta.NextToken == "" {
				break
			}
		}
		allListMembers[list.ID] = listMembers
	}
	listmembersJson, err := json.Marshal(allListMembers)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to marshal list members amp to json")
	}
	err = os.WriteFile("listmembers.json", listmembersJson, 0660)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to save list members to file")
	}
}

func waitForRateLimit(rl *twitter.RateLimit) {
	if rl.Remaining == 0 {
		log.Info().Time("reset", rl.Reset.Time()).Msg("We have been rate limited!")
		time.Sleep(time.Until(rl.Reset.Time()))
		log.Info().Msg("Done sleeping")
	}

}

func getClient(accessToken string) *twitter.Client {
	log.Trace().Str("token", accessToken).Msg("Current API Token")
	client := &twitter.Client{
		Authorizer: authorize{
			Token: accessToken,
		},
		Client: http.DefaultClient,
		Host:   "https://api.twitter.com",
	}
	return client
}

func getToken() *twitterToken {
	if tok := os.Getenv("TWITTER_ACCESS_TOKEN"); tok != "" {
		t := new(twitterToken)
		t.AccessToken = tok
		return t
	}
	u, _ := url.Parse("https://twitter.com/i/oauth2/authorize?response_type=code&scope=tweet.read%20list.read%20users.read%20follows.read%20offline.access &state=state&code_challenge=challenge&code_challenge_method=plain")
	q := u.Query()
	q.Set("client_id", os.Getenv("TWITTER_CLIENT_ID"))
	q.Set("redirect_uri", os.Getenv("TWITTER_REDIRECT_URI"))
	u.RawQuery = q.Encode()

	fmt.Println("Open the following URL in your browser and authorize the app:")
	fmt.Println(u)
	fmt.Println("Paste the code from the redirect url here:")
	var code string
	_, err := fmt.Scanf("%s", &code)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read code")
	}

	log.Trace().Str("code", code).Msg("Got code")

	u, _ = url.Parse("https://api.twitter.com/2/oauth2/token")
	q = make(url.Values)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")
	q.Set("client_id", os.Getenv("TWITTER_CLIENT_ID"))
	q.Set("redirect_uri", os.Getenv("TWITTER_REDIRECT_URI"))
	q.Set("code_verifier", "challenge")

	buf := bytes.NewBuffer([]byte(q.Encode()))
	resp, err := http.Post(u.String(), "application/x-www-form-urlencoded", buf)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to exchange token")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatal().Int("code", resp.StatusCode).Str("status", resp.Status).Msg("Got an unexpected status code")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to read response body")
	}
	var tok = new(twitterToken)
	err = json.Unmarshal(body, tok)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to marshal json")
	}
	fmt.Println(tok)
	return tok
}
