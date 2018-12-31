using BouncyCastle.Core.Port;
using BouncyCastle.Core.Port.java.text;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.bc
{

	
	/// <summary>
	/// <pre>
	/// ObjectData ::= SEQUENCE {
	///     type             INTEGER,
	///     identifier       UTF8String,
	///     creationDate     GeneralizedTime,
	///     lastModifiedDate GeneralizedTime,
	///     data             OCTET STRING,
	///     comment          UTF8String OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class ObjectData : ASN1Object
	{
		private readonly BigInteger type;
		private readonly string identifier;
		private readonly ASN1GeneralizedTime creationDate;
		private readonly ASN1GeneralizedTime lastModifiedDate;
		private readonly ASN1OctetString data;
		private readonly string comment;

		private ObjectData(ASN1Sequence seq)
		{
			this.type = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
			this.identifier = DERUTF8String.getInstance(seq.getObjectAt(1)).getString();
			this.creationDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
			this.lastModifiedDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
			this.data = ASN1OctetString.getInstance(seq.getObjectAt(4));
			this.comment = (seq.size() == 6) ? DERUTF8String.getInstance(seq.getObjectAt(5)).getString() : null;
		}

		public ObjectData(BigInteger type, string identifier, DateTime creationDate, DateTime lastModifiedDate, byte[] data, string comment)
		{
			this.type = type;
			this.identifier = identifier;
			this.creationDate = new DERGeneralizedTime(creationDate);
			this.lastModifiedDate = new DERGeneralizedTime(lastModifiedDate);
			this.data = new DEROctetString(Arrays.clone(data));
			this.comment = comment;
		}

		public static ObjectData getInstance(object obj)
		{
			if (obj is ObjectData)
			{
				return (ObjectData)obj;
			}
			else if (obj != null)
			{
				return new ObjectData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual string getComment()
		{
			return comment;
		}

		public virtual ASN1GeneralizedTime getCreationDate()
		{
			return creationDate;
		}

		public virtual byte[] getData()
		{
			return Arrays.clone(data.getOctets());
		}

		public virtual string getIdentifier()
		{
			return identifier;
		}

		public virtual ASN1GeneralizedTime getLastModifiedDate()
		{
			return lastModifiedDate;
		}

		public virtual BigInteger getType()
		{
			return type;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(type));
			v.add(new DERUTF8String(identifier));
			v.add(creationDate);
			v.add(lastModifiedDate);
			v.add(data);

			if (!string.ReferenceEquals(comment, null))
			{
				v.add(new DERUTF8String(comment));
			}

			return new DERSequence(v);
		}
	}

}