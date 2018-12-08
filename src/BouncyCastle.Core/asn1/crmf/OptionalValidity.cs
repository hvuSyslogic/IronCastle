using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.crmf
{

	using Time = org.bouncycastle.asn1.x509.Time;

	public class OptionalValidity : ASN1Object
	{
		private Time notBefore;
		private Time notAfter;

		private OptionalValidity(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();
			while (en.hasMoreElements())
			{
				ASN1TaggedObject tObj = (ASN1TaggedObject)en.nextElement();

				if (tObj.getTagNo() == 0)
				{
					notBefore = Time.getInstance(tObj, true);
				}
				else
				{
					notAfter = Time.getInstance(tObj, true);
				}
			}
		}

		public static OptionalValidity getInstance(object o)
		{
			if (o is OptionalValidity)
			{
				return (OptionalValidity)o;
			}

			if (o != null)
			{
				return new OptionalValidity(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public OptionalValidity(Time notBefore, Time notAfter)
		{
			if (notBefore == null && notAfter == null)
			{
				throw new IllegalArgumentException("at least one of notBefore/notAfter must not be null.");
			}

			this.notBefore = notBefore;
			this.notAfter = notAfter;
		}

		public virtual Time getNotBefore()
		{
			return notBefore;
		}

		public virtual Time getNotAfter()
		{
			return notAfter;
		}

		/// <summary>
		/// <pre>
		/// OptionalValidity ::= SEQUENCE {
		///                        notBefore  [0] Time OPTIONAL,
		///                        notAfter   [1] Time OPTIONAL } --at least one MUST be present
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (notBefore != null)
			{
				v.add(new DERTaggedObject(true, 0, notBefore));
			}

			if (notAfter != null)
			{
				v.add(new DERTaggedObject(true, 1, notAfter));
			}

			return new DERSequence(v);
		}
	}

}