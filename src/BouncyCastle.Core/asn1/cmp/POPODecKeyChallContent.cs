namespace org.bouncycastle.asn1.cmp
{

	public class POPODecKeyChallContent : ASN1Object
	{
		private ASN1Sequence content;

		private POPODecKeyChallContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static POPODecKeyChallContent getInstance(object o)
		{
			if (o is POPODecKeyChallContent)
			{
				return (POPODecKeyChallContent)o;
			}

			if (o != null)
			{
				return new POPODecKeyChallContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual Challenge[] toChallengeArray()
		{
			Challenge[] result = new Challenge[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = Challenge.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// POPODecKeyChallContent ::= SEQUENCE OF Challenge
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}