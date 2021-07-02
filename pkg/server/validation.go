package server

import "net/mail"

const StringLengthMin = 5
const StringLengthMax = 24
const PasswordLengthMin = 5
const PasswordLengthMax = 18

type ValidationBag struct {
	Responses map[string]ValidationReponse
}

func (r *ValidationBag) Clear() {
	for k := range r.Responses {
		delete(r.Responses, k)
	}
}

func (r *ValidationBag) Valid() bool {
	for _, r := range r.Responses {
		if !r.Valid() {
			return false
		}
	}

	return true
}

func newValidationBag() *ValidationBag {
	bag := ValidationBag{
		Responses: make(map[string]ValidationReponse),
	}

	return &bag
}

type ValidationReponse string

func (r *ValidationReponse) Valid() bool {
	return *r == ""
}

func validateEmail(email string) ValidationReponse {
	response := ValidationReponse("")

	_, err := mail.ParseAddress(email)
	if err != nil {
		response = "invalid email format"
	}

	return response
}

func validateStringField(str string, min int, max int) ValidationReponse {
	response := ValidationReponse("")

	if len(str) < min {
		response = "field value is too short"
	}

	if len(str) > max {
		response = "field value is too long"
	}

	return response
}

func validatePassword(bag *ValidationBag, password string, confirm string) {
	pwResponse := validateStringField(password, PasswordLengthMin, PasswordLengthMax)
	if !pwResponse.Valid() {
		bag.Responses["password"] = pwResponse
	}

	if password != confirm {
		bag.Responses["confirm_password"] = "passwords must match"
	}
}

func validateDisplayName(bag *ValidationBag, displayName string) {
	lengthResponse := validateStringField(displayName, StringLengthMin, StringLengthMax)
	if !lengthResponse.Valid() {
		bag.Responses["display_name"] = lengthResponse
	}
}
