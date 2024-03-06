package email

import (
	"os"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type SendEmailOptions struct {
	fromMail string
	fromName string
	toMail   string
	toName   string

	subject string
	text    string
	html    string
}

func sendEmail(sendEmailOptions SendEmailOptions) error {
	from := &mail.Email{
		Address: sendEmailOptions.fromMail,
		Name:    sendEmailOptions.fromName,
	}
	to := &mail.Email{
		Address: sendEmailOptions.toMail,
		Name:    sendEmailOptions.toName,
	}
	message := mail.NewSingleEmail(from, sendEmailOptions.subject, to, sendEmailOptions.text, sendEmailOptions.html)
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_KEY"))

	_, err := client.Send(message)
	if err != nil {
		return err
	}

	return nil
}

func SendWelcomeEmail(to string) error {
	options := SendEmailOptions{
		fromMail: "default@email.com",
		fromName: "Default Name",
		toMail:   to,
		subject:  "Welcome aboard",
		text:     "",
		html:     "<h5>Welcome to the team</h5>",
	}

	return sendEmail(options)
}
