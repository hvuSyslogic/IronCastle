using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.cmp
{


	public class PollReqContent : ASN1Object
	{
		private ASN1Sequence content;

		private PollReqContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static PollReqContent getInstance(object o)
		{
			if (o is PollReqContent)
			{
				return (PollReqContent)o;
			}

			if (o != null)
			{
				return new PollReqContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// Create a pollReqContent for a single certReqId.
		/// </summary>
		/// <param name="certReqId"> the certificate request ID. </param>
		public PollReqContent(ASN1Integer certReqId) : this(new DERSequence(new DERSequence(certReqId)))
		{
		}

		/// <summary>
		/// Create a pollReqContent for a multiple certReqIds.
		/// </summary>
		/// <param name="certReqIds"> the certificate request IDs. </param>
		public PollReqContent(ASN1Integer[] certReqIds) : this(new DERSequence(intsToSequence(certReqIds)))
		{
		}

		/// <summary>
		/// Create a pollReqContent for a single certReqId.
		/// </summary>
		/// <param name="certReqId"> the certificate request ID. </param>
		public PollReqContent(BigInteger certReqId) : this(new ASN1Integer(certReqId))
		{
		}

		/// <summary>
		/// Create a pollReqContent for a multiple certReqIds.
		/// </summary>
		/// <param name="certReqIds"> the certificate request IDs. </param>
		public PollReqContent(BigInteger[] certReqIds) : this(intsToASN1(certReqIds))
		{
		}

		public virtual ASN1Integer[][] getCertReqIds()
		{
			ASN1Integer[][] result = new ASN1Integer[content.size()][];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = sequenceToASN1IntegerArray((ASN1Sequence)content.getObjectAt(i));
			}

			return result;
		}

		public virtual BigInteger[] getCertReqIdValues()
		{
			BigInteger[] result = new BigInteger[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = ASN1Integer.getInstance(ASN1Sequence.getInstance(content.getObjectAt(i)).getObjectAt(0)).getValue();
			}

			return result;
		}

		private static ASN1Integer[] sequenceToASN1IntegerArray(ASN1Sequence seq)
		{
			ASN1Integer[] result = new ASN1Integer[seq.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = ASN1Integer.getInstance(seq.getObjectAt(i));
			}

			return result;
		}

		private static DERSequence[] intsToSequence(ASN1Integer[] ids)
		{
			DERSequence[] result = new DERSequence[ids.Length];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = new DERSequence(ids[i]);
			}

			return result;
		}

		private static ASN1Integer[] intsToASN1(BigInteger[] ids)
		{
			ASN1Integer[] result = new ASN1Integer[ids.Length];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = new ASN1Integer(ids[i]);
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// PollReqContent ::= SEQUENCE OF SEQUENCE {
		///                        certReqId              INTEGER
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}