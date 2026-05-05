// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("parseBootstrapToken", func() {
	It("splits a valid token into id and secret", func() {
		id, secret, err := parseBootstrapToken("abcdef.0123456789abcdef")
		Expect(err).NotTo(HaveOccurred())
		Expect(id).To(Equal("abcdef"))
		Expect(secret).To(Equal("0123456789abcdef"))
	})

	DescribeTable("rejects malformed tokens",
		func(token string) {
			_, _, err := parseBootstrapToken(token)
			Expect(err).To(MatchError(ContainSubstring("invalid bootstrap token format")))
		},
		Entry("empty", ""),
		Entry("missing separator", "abcdef0123456789abcdef"),
		Entry("missing secret", "abcdef."),
		Entry("missing id", ".0123456789abcdef"),
		Entry("id too short", "abcde.0123456789abcdef"),
		Entry("id too long", "abcdefg.0123456789abcdef"),
		Entry("secret too short", "abcdef.0123"),
		Entry("secret too long", "abcdef.0123456789abcdefg"),
		Entry("uppercase in id", "ABCDEF.0123456789abcdef"),
		Entry("uppercase in secret", "abcdef.0123456789ABCDEF"),
		Entry("special char in id", "abc-ef.0123456789abcdef"),
		Entry("special char in secret", "abcdef.0123456789abc@ef"),
		Entry("extra dot", "abcdef.01234567.9abcdef"),
		Entry("only whitespace", "      .                "),
	)
})
