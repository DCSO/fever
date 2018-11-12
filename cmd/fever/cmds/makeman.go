package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// mmanCmd represents the makeman command
var mmanCmd = &cobra.Command{
	Use:   "makeman [options]",
	Short: "Create man pages",
	Run: func(cmd *cobra.Command, args []string) {
		targetDir, err := cmd.Flags().GetString("dir")
		if err != nil {
			log.Fatal(err)
		}
		header := &doc.GenManHeader{}
		err = doc.GenManTree(rootCmd, header, targetDir)
		if err != nil {
			log.Fatal(err)
		}
		for _, v := range rootCmd.Commands() {
			err = doc.GenManTree(v, header, targetDir)
			if err != nil {
				log.Fatal(err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(mmanCmd)
	mmanCmd.Flags().StringP("dir", "d", ".", "target directory for man pages")
}
