package utils

import "strconv"

func FormatWithCommas(number uint64) string {
	in := strconv.FormatUint(number, 10)
	out := make([]byte, 0, len(in)+(len(in)-1)/3)

	for i := 0; i < len(in); i++ {
		if i != 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, in[i])
	}

	return string(out)
}
