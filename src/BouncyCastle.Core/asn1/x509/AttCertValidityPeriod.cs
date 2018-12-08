using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class AttCertValidityPeriod : ASN1Object
	{
		internal ASN1GeneralizedTime notBeforeTime;
		internal ASN1GeneralizedTime notAfterTime;

		public static AttCertValidityPeriod getInstance(object obj)
		{
			if (obj is AttCertValidityPeriod)
			{
				return (AttCertValidityPeriod)obj;
			}
			else if (obj != null)
			{
				return new AttCertValidityPeriod(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private AttCertValidityPeriod(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			notBeforeTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(0));
			notAfterTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
		}

		/// <param name="notBeforeTime"> </param>
		/// <param name="notAfterTime"> </param>
		public AttCertValidityPeriod(ASN1GeneralizedTime notBeforeTime, ASN1GeneralizedTime notAfterTime)
		{
			this.notBeforeTime = notBeforeTime;
			this.notAfterTime = notAfterTime;
		}

		public virtual ASN1GeneralizedTime getNotBeforeTime()
		{
			return notBeforeTime;
		}

		public virtual ASN1GeneralizedTime getNotAfterTime()
		{
			return notAfterTime;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  AttCertValidityPeriod  ::= SEQUENCE {
		///       notBeforeTime  GeneralizedTime,
		///       notAfterTime   GeneralizedTime
		///  } 
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(notBeforeTime);
			v.add(notAfterTime);

			return new DERSequence(v);
		}
	}

}