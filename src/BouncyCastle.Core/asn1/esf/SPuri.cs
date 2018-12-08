namespace org.bouncycastle.asn1.esf
{

	public class SPuri
	{
		private DERIA5String uri;

		public static SPuri getInstance(object obj)
		{
			if (obj is SPuri)
			{
				return (SPuri) obj;
			}
			else if (obj is DERIA5String)
			{
				return new SPuri(DERIA5String.getInstance(obj));
			}

			return null;
		}

		public SPuri(DERIA5String uri)
		{
			this.uri = uri;
		}

		public virtual DERIA5String getUri()
		{
			return uri;
		}

		/// <summary>
		/// <pre>
		/// SPuri ::= IA5String
		/// </pre>
		/// </summary>
		public virtual ASN1Primitive toASN1Primitive()
		{
			return uri.toASN1Primitive();
		}
	}

}