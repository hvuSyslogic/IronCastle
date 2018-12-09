﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.esf
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// <pre>
	///  CrlIdentifier ::= SEQUENCE 
	/// {
	///   crlissuer    Name,
	///   crlIssuedTime  UTCTime,
	///   crlNumber    INTEGER OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class CrlIdentifier : ASN1Object
	{
		private X500Name crlIssuer;
		private ASN1UTCTime crlIssuedTime;
		private ASN1Integer crlNumber;

		public static CrlIdentifier getInstance(object obj)
		{
			if (obj is CrlIdentifier)
			{
				return (CrlIdentifier)obj;
			}
			else if (obj != null)
			{
				return new CrlIdentifier(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private CrlIdentifier(ASN1Sequence seq)
		{
			if (seq.size() < 2 || seq.size() > 3)
			{
				throw new IllegalArgumentException();
			}
			this.crlIssuer = X500Name.getInstance(seq.getObjectAt(0));
			this.crlIssuedTime = ASN1UTCTime.getInstance(seq.getObjectAt(1));
			if (seq.size() > 2)
			{
				this.crlNumber = ASN1Integer.getInstance(seq.getObjectAt(2));
			}
		}

		public CrlIdentifier(X500Name crlIssuer, ASN1UTCTime crlIssuedTime) : this(crlIssuer, crlIssuedTime, null)
		{
		}

		public CrlIdentifier(X500Name crlIssuer, ASN1UTCTime crlIssuedTime, BigInteger crlNumber)
		{
			this.crlIssuer = crlIssuer;
			this.crlIssuedTime = crlIssuedTime;
			if (null != crlNumber)
			{
				this.crlNumber = new ASN1Integer(crlNumber);
			}
		}

		public virtual X500Name getCrlIssuer()
		{
			return this.crlIssuer;
		}

		public virtual ASN1UTCTime getCrlIssuedTime()
		{
			return this.crlIssuedTime;
		}

		public virtual BigInteger getCrlNumber()
		{
			if (null == this.crlNumber)
			{
				return null;
			}
			return this.crlNumber.getValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(this.crlIssuer.toASN1Primitive());
			v.add(this.crlIssuedTime);
			if (null != this.crlNumber)
			{
				v.add(this.crlNumber);
			}
			return new DERSequence(v);
		}

	}

}