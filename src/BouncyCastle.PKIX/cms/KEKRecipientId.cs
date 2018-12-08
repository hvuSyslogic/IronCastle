namespace org.bouncycastle.cms
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class KEKRecipientId : RecipientId
	{
		private byte[] keyIdentifier;

		/// <summary>
		/// Construct a recipient ID with the key identifier of a KEK recipient.
		/// </summary>
		/// <param name="keyIdentifier"> a subjectKeyId </param>
		public KEKRecipientId(byte[] keyIdentifier) : base(kek)
		{

			this.keyIdentifier = keyIdentifier;
		}

		public override int GetHashCode()
		{
			return Arrays.GetHashCode(keyIdentifier);
		}

		public override bool Equals(object o)
		{
			if (!(o is KEKRecipientId))
			{
				return false;
			}

			KEKRecipientId id = (KEKRecipientId)o;

			return Arrays.areEqual(keyIdentifier, id.keyIdentifier);
		}

		public virtual byte[] getKeyIdentifier()
		{
			return Arrays.clone(keyIdentifier);
		}

		public override object clone()
		{
			return new KEKRecipientId(keyIdentifier);
		}

		public virtual bool match(object obj)
		{
			if (obj is byte[])
			{
				return Arrays.areEqual(keyIdentifier, (byte[])obj);
			}
			else if (obj is KEKRecipientInformation)
			{
				return ((KEKRecipientInformation)obj).getRID().Equals(this);
			}

			return false;
		}
	}

}