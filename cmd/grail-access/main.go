// Copyright 2018 GRAIL, Inc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

// The following enables go generate to generate the doc.go file.
//go:generate go run v.io/x/lib/cmdline/gendoc "--build-cmd=go install" --copyright-notice= . -help
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/grailbio/base/errors"

	_ "github.com/grailbio/v23/factories/grail"
	v23 "v.io/v23"
	"v.io/v23/security"
	"v.io/x/lib/cmdline"
	"v.io/x/ref"
	libsecurity "v.io/x/ref/lib/security"
	"v.io/x/ref/services/agent/agentlib"
)

const (
	// DATA(sensitive): These are the OAuth2 client ID and secret. They were
	// generated in the grail-razvanm Google Cloud Project. The client secret
	// is not secret in this case because it is part of client tool. It does act
	// as an identifier that allows restriction based on quota on the Google
	// side.
	clientID     = "27162366543-edih9cqc3t8p5hn9ord1k1n7h4oajfhm.apps.googleusercontent.com"
	clientSecret = "eRZyFfe5xJu0083zDk8Mlb6K"
)

var (
	credentialsDirFlag string
	ec2Flag            bool

	blesserGoogleFlag string
	browserFlag       bool

	blesserEc2Flag       string
	identityDocumentFlag string

	dumpFlag                 bool
	doNotRefreshDurationFlag time.Duration
)

func main() {
	var defaultCredentialsDir string
	if dir, ok := os.LookupEnv(ref.EnvCredentials); ok {
		defaultCredentialsDir = dir
	} else {
		defaultCredentialsDir = os.ExpandEnv("${HOME}/.v23")
	}

	cmd := &cmdline.Command{
		Runner: cmdline.RunnerFunc(run),
		Name:   "grail-access",
		Short:  "Creates fresh Vanadium credentials",
		Long: `
Command grail-access creates Vanadium credentials (also called principals) using
either Google ID tokens (the default) or the AWS IAM role attached to an EC2
instance (requested using the '-ec2' flag).

For the Google-based auth the user will be prompted to go through an
OAuth flow that requires minimal permissions (only 'Know who you are
on Google') and obtains an ID token scoped to the clientID expected by
the server. The ID token is presented to the server via a Vanadium
RPC. For a 'xxx@grailbio.com' email address the server will hand to
the client a '[server]:google:xxx@grailbio.com' blessing where
'[server]' is the blessing of the server.

For the EC2-based auth an instance with ID 'i-0aec7b085f8432699' in the account
number '619867110810' using the 'adhoc' role the server will hand to the client
a '[server]:ec2:619867110810:role:adhoc:i-0aec7b085f8432699' blessing where
'server' is the blessing of the server.
`,
	}
	cmd.Flags.StringVar(&blesserGoogleFlag, "blesser-google", "/ticket-server.eng.grail.com:8102/blesser/google", "Blesser to talk to for the Google-based flow.")
	cmd.Flags.StringVar(&blesserEc2Flag, "blesser-ec2", "/ticket-server.eng.grail.com:8102/blesser/ec2", "Blesser to talk to for the EC2-based flow.")
	cmd.Flags.StringVar(&credentialsDirFlag, "dir", defaultCredentialsDir, "Where to store the Vanadium credentials. NOTE: the content will be erased if the credentials are regenerated.")
	cmd.Flags.BoolVar(&ec2Flag, "ec2", false, "Use the role of the EC2 VM.")
	cmd.Flags.BoolVar(&browserFlag, "browser", os.Getenv("SSH_CLIENT") == "", "Attempt to open a browser.")
	cmd.Flags.BoolVar(&dumpFlag, "dump", false, "If credentials are present, dump them on the console instead of refreshing them.")
	cmd.Flags.DurationVar(&doNotRefreshDurationFlag, "do-not-refresh-duration", 7*24*time.Hour, "Do not refresh credentials if they are present and do not expire within this duration.")

	cmdline.HideGlobalFlagsExcept()
	cmdline.Main(cmd)
}

func run(*cmdline.Env, []string) error {
	ctx, shutDown := v23.Init()
	defer shutDown()

	if _, ok := os.LookupEnv(ref.EnvCredentials); !ok {
		fmt.Print("*******************************************************\n")
		fmt.Printf("*    WARNING: $%s is not defined!        *\n", ref.EnvCredentials)
		fmt.Printf("*******************************************************\n\n")
		fmt.Printf("How to fix this in bash: export %s=%s\n\n", ref.EnvCredentials, credentialsDirFlag)
	}
	principal, err := agentlib.LoadPrincipal(credentialsDirFlag)
	if err != nil && os.IsNotExist(err) {
		fmt.Printf("INFO: Creating new principal at: %s", credentialsDirFlag)
		// TODO(josh): Do we need to kill the v23agentd?
		_, err = libsecurity.CreatePersistentPrincipal(credentialsDirFlag, nil)
		if err != nil {
			return errors.E("failed to create new principal", err)
		}
		principal, err = agentlib.LoadPrincipal(credentialsDirFlag)
	}
	if err != nil {
		return errors.E("failed to load principal", err)
	}

	defaultBlessings, _ := principal.BlessingStore().Default()
	if dumpFlag || defaultBlessings.Expiry().After(time.Now().Add(doNotRefreshDurationFlag)) {
		dump(principal)
		return nil
	}

	ctx, err = v23.WithPrincipal(ctx, principal)
	if err != nil {
		return errors.E("failed to set context principal", err)
	}
	var blessings security.Blessings
	if ec2Flag {
		blessings, err = fetchEC2Blessings(ctx)
	} else {
		blessings, err = fetchGoogleBlessings(ctx)
	}
	if err != nil {
		return errors.E("failed to fetch blessings", err)
	}

	if err := principal.BlessingStore().SetDefault(blessings); err != nil {
		return errors.E(err, "failed to set default blessings")
	}
	_, err = principal.BlessingStore().Set(blessings, "...") // TODO(josh): What is this?
	if err != nil {
		return errors.E(err, "failed to set peer blessings")
	}
	if err := security.AddToRoots(principal, blessings); err != nil {
		return errors.E(err, "failed to add blessing roots")
	}

	fmt.Println("Successfully applied new blessing:")
	dump(principal)

	if err := principal.Close(); err != nil {
		errors.E("failed to close agent principal", err)
	}
	return nil
}

func dump(principal security.Principal) {
	// Mimic the output of the v.io/x/ref/cmd/principal dump command.
	fmt.Printf("Public key: %s\n", principal.PublicKey())
	fmt.Println("---------------- BlessingStore ----------------")
	fmt.Print(principal.BlessingStore().DebugString())
	fmt.Println("---------------- BlessingRoots ----------------")
	fmt.Print(principal.Roots().DebugString())

	blessing, _ := principal.BlessingStore().Default()
	fmt.Printf("Expires on %s (in %s)\n", blessing.Expiry().Local(), time.Until(blessing.Expiry()))
}
