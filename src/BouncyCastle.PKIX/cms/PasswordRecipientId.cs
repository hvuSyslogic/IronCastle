namespace org.bouncycastle.cms
{
	public class PasswordRecipientId : RecipientId
	{
		/// <summary>
		/// Construct a recipient ID of the password type.
		/// </summary>
		public PasswordRecipientId() : base(password)
		{
		}

		public override int GetHashCode()
		{
			return password;
		}

		public override bool Equals(object o)
		{
			if (!(o is PasswordRecipientId))
			{
				return false;
			}

			return true;
		}

		public override object clone()
		{
			return new PasswordRecipientId();
		}

		public virtual bool match(object obj)
		{
			if (obj is PasswordRecipientInformation)
			{
				return true;
			}

			return false;
		}
	}

}