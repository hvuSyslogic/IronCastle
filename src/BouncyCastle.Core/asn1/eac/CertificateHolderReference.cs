using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.asn1.eac
{

	public class CertificateHolderReference
	{
		private const string ReferenceEncoding = "ISO-8859-1";

		private string countryCode;
		private string holderMnemonic;
		private string sequenceNumber;

		public CertificateHolderReference(string countryCode, string holderMnemonic, string sequenceNumber)
		{
			this.countryCode = countryCode;
			this.holderMnemonic = holderMnemonic;
			this.sequenceNumber = sequenceNumber;
		}

		public CertificateHolderReference(byte[] contents)
		{
			try
			{
				string concat = StringHelper.NewString(contents, ReferenceEncoding);

				this.countryCode = concat.Substring(0, 2);
				this.holderMnemonic = concat.Substring(2, (concat.Length - 5) - 2);

				this.sequenceNumber = concat.Substring(concat.Length - 5);
			}
			catch (UnsupportedEncodingException e)
			{
				throw new IllegalStateException(e.ToString());
			}
		}

		public virtual string getCountryCode()
		{
			return countryCode;
		}

		public virtual string getHolderMnemonic()
		{
			return holderMnemonic;
		}

		public virtual string getSequenceNumber()
		{
			return sequenceNumber;
		}


		public virtual byte[] getEncoded()
		{
			string @ref = countryCode + holderMnemonic + sequenceNumber;

			try
			{
				return @ref.GetBytes(ReferenceEncoding);
			}
			catch (UnsupportedEncodingException e)
			{
				throw new IllegalStateException(e.ToString());
			}
		}
	}

}