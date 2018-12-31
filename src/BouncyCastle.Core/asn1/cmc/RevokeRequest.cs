using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.cmc
{

			
	/// <summary>
	/// <pre>
	/// RevokeRequest ::= SEQUENCE {
	///     issuerName            Name,
	///     serialNumber          INTEGER,
	///     reason                CRLReason,
	///     invalidityDate         GeneralizedTime OPTIONAL,
	///     passphrase            OCTET STRING OPTIONAL,
	///     comment               UTF8String OPTIONAL }
	/// </pre>
	/// </summary>
	public class RevokeRequest : ASN1Object
	{
		private readonly X500Name name;
		private readonly ASN1Integer serialNumber;
		private readonly CRLReason reason;

		private ASN1GeneralizedTime invalidityDate;
		private ASN1OctetString passphrase;
		private DERUTF8String comment;

		public RevokeRequest(X500Name name, ASN1Integer serialNumber, CRLReason reason, ASN1GeneralizedTime invalidityDate, ASN1OctetString passphrase, DERUTF8String comment)
		{
			this.name = name;
			this.serialNumber = serialNumber;
			this.reason = reason;
			this.invalidityDate = invalidityDate;
			this.passphrase = passphrase;
			this.comment = comment;
		}

		private RevokeRequest(ASN1Sequence seq)
		{
			if (seq.size() < 3 || seq.size() > 6)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.name = X500Name.getInstance(seq.getObjectAt(0));
			this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
			this.reason = CRLReason.getInstance(seq.getObjectAt(2));

			int index = 3;
			if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() is ASN1GeneralizedTime)
			{
				this.invalidityDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(index++));
			}
			if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() is ASN1OctetString)
			{
				this.passphrase = ASN1OctetString.getInstance(seq.getObjectAt(index++));
			}
			if (seq.size() > index && seq.getObjectAt(index).toASN1Primitive() is DERUTF8String)
			{
				this.comment = DERUTF8String.getInstance(seq.getObjectAt(index));
			}
		}

		public static RevokeRequest getInstance(object o)
		{
			if (o is RevokeRequest)
			{
				return (RevokeRequest)o;
			}

			if (o != null)
			{
				return new RevokeRequest(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual X500Name getName()
		{
			return name;
		}

		public virtual BigInteger getSerialNumber()
		{
			return serialNumber.getValue();
		}

		public virtual CRLReason getReason()
		{
			return reason;
		}

		public virtual ASN1GeneralizedTime getInvalidityDate()
		{
			return invalidityDate;
		}

		public virtual void setInvalidityDate(ASN1GeneralizedTime invalidityDate)
		{
			this.invalidityDate = invalidityDate;
		}

		public virtual ASN1OctetString getPassphrase()
		{
			return passphrase;
		}

		public virtual void setPassphrase(ASN1OctetString passphrase)
		{
			this.passphrase = passphrase;
		}

		public virtual DERUTF8String getComment()
		{
			return comment;
		}

		public virtual void setComment(DERUTF8String comment)
		{
			this.comment = comment;
		}

		public virtual byte[] getPassPhrase()
		{
			if (passphrase != null)
			{
				return Arrays.clone(passphrase.getOctets());
			}
			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(name);
			v.add(serialNumber);
			v.add(reason);

			if (invalidityDate != null)
			{
				v.add(invalidityDate);
			}
			if (passphrase != null)
			{
				v.add(passphrase);
			}
			if (comment != null)
			{
				v.add(comment);
			}

			return new DERSequence(v);
		}
	}

}