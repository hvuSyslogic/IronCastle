namespace org.bouncycastle.dvcs
{
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;

	public class MessageImprint
	{
		private readonly DigestInfo messageImprint;

		public MessageImprint(DigestInfo messageImprint)
		{
			this.messageImprint = messageImprint;
		}

		public virtual DigestInfo toASN1Structure()
		{
			return messageImprint;
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (o is MessageImprint)
			{
				return messageImprint.Equals(((MessageImprint)o).messageImprint);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return messageImprint.GetHashCode();
		}
	}

}