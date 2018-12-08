using System;

namespace org.bouncycastle.mail.smime.validator
{
	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using LocalizedException = org.bouncycastle.i18n.LocalizedException;

	public class SignedMailValidatorException : LocalizedException
	{

		public SignedMailValidatorException(ErrorBundle errorMessage, Exception throwable) : base(errorMessage, throwable)
		{
		}

		public SignedMailValidatorException(ErrorBundle errorMessage) : base(errorMessage)
		{
		}

	}

}