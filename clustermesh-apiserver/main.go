// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/clustermesh-apiserver/apiserver"
	"github.com/cilium/cilium/pkg/hive"
)

func main() {
	cmd := &cobra.Command{
		Use:   "clustermesh-apiserver",
		Short: "Run the ClusterMesh apiserver",
	}

	cmd.AddCommand(
		apiserver.NewCmd(hive.New(apiserver.Cell)),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
