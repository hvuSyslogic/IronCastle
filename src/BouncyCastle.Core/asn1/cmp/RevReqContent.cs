namespace org.bouncycastle.asn1.cmp
{

	public class RevReqContent : ASN1Object
	{
		private ASN1Sequence content;

		private RevReqContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static RevReqContent getInstance(object o)
		{
			if (o is RevReqContent)
			{
				return (RevReqContent)o;
			}

			if (o != null)
			{
				return new RevReqContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public RevReqContent(RevDetails revDetails)
		{
			this.content = new DERSequence(revDetails);
		}

		public RevReqContent(RevDetails[] revDetailsArray)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != revDetailsArray.Length; i++)
			{
				v.add(revDetailsArray[i]);
			}

			this.content = new DERSequence(v);
		}

		public virtual RevDetails[] toRevDetailsArray()
		{
			RevDetails[] result = new RevDetails[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = RevDetails.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// RevReqContent ::= SEQUENCE OF RevDetails
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}