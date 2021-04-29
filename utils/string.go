package utils

func Contains(slice []string, str string) (index int, ok bool) {

	for i := range slice {

		if slice[i] == str {

			return i, true

		}

	}

	return -1, false
}
