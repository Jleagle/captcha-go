# recaptcha-go

```go
import "github.com/Jleagle/recaptcha-go"

func FormHandler(w http.ResponseWriter, r *http.Request) {

    err = recaptcha.CheckFromRequest(r)
    if err != nil {
        if err == recaptcha.ErrNotChecked {
            return ErrInvalidCaptcha
        } else {
            logger.Error(err)
            return err
        }
    }

}
```
