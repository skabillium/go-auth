package email

import (
	"bytes"
	"context"
	"os"
	"strings"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"skabillium.io/auth-service/cmd/templates"
)

type SendEmailOptions struct {
	toMail string
	toName string

	subject string
	text    string
	html    string
}

func sendEmail(sendEmailOptions SendEmailOptions) error {
	from := &mail.Email{
		Address: "auth@email.com",
		Name:    "Auth Platform",
	}
	to := &mail.Email{
		Address: sendEmailOptions.toMail,
		Name:    sendEmailOptions.toName,
	}

	debugMail := os.Getenv("DEBUG_MAIL")
	if debugMail != "" {
		split := strings.Split(debugMail, "@")
		debugUser := split[0]
		debugDomain := split[1]

		to = &mail.Email{
			Address: debugUser + "+" + replaceSpecialChars(to.Address) + "@" + debugDomain,
			Name:    "Default Name",
		}
	}

	message := mail.NewSingleEmail(from, sendEmailOptions.subject, to, sendEmailOptions.text, sendEmailOptions.html)
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_KEY"))

	_, err := client.Send(message)
	if err != nil {
		return err
	}

	return nil
}

func replaceSpecialChars(email string) string {
	return strings.ReplaceAll(email, "@", "__")
}

func SendRegistrationEmail(to string, url string) error {
	var buffer bytes.Buffer
	verificationEmailTemplate := templates.RegistrationEmail(url)
	verificationEmailTemplate.Render(context.Background(), &buffer)

	options := SendEmailOptions{
		toMail:  to,
		subject: "Welcome aboard",
		html:    buffer.String(),
	}
	return sendEmail(options)
}

func SendVerificationEmail(to string, url string) error {
	var buffer bytes.Buffer
	verificationEmailTemplate := templates.VerificationEmail(url)
	verificationEmailTemplate.Render(context.Background(), &buffer)

	options := SendEmailOptions{
		toMail:  to,
		subject: "Welcome aboard",
		html:    buffer.String(),
	}
	return sendEmail(options)
}

func SendPasswordResetEmail(to string, url string) error {

	var buffer bytes.Buffer
	resetPasswordTemplate := templates.ResetPasswordEmail(url)
	resetPasswordTemplate.Render(context.Background(), &buffer)

	options := SendEmailOptions{
		toMail:  to,
		subject: "Reset password",
		html:    buffer.String(),
	}
	return sendEmail(options)
}
