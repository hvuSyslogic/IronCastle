using System;
using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <pre>
	/// ObjectStoreData ::= SEQUENCE {
	///     version INTEGER.
	///     dataSalt OCTET STRING,
	///     integrityAlgorithm AlgorithmIdentifier,
	///     creationDate GeneralizedTime,
	///     lastModifiedDate GeneralizedTime,
	///     objectDataSequence ObjectDataSequence,
	///     comment UTF8String OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class ObjectStoreData : ASN1Object
	{
		private readonly BigInteger version;
		private readonly AlgorithmIdentifier integrityAlgorithm;
		private readonly ASN1GeneralizedTime creationDate;
		private readonly ASN1GeneralizedTime lastModifiedDate;
		private readonly ObjectDataSequence objectDataSequence;
		private readonly string comment;

		public ObjectStoreData(AlgorithmIdentifier integrityAlgorithm, DateTime creationDate, DateTime lastModifiedDate, ObjectDataSequence objectDataSequence, string comment)
		{
			this.version = BigInteger.valueOf(1);
			this.integrityAlgorithm = integrityAlgorithm;
			this.creationDate = new DERGeneralizedTime(creationDate);
			this.lastModifiedDate = new DERGeneralizedTime(lastModifiedDate);
			this.objectDataSequence = objectDataSequence;
			this.comment = comment;
		}

		private ObjectStoreData(ASN1Sequence seq)
		{
			this.version = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
			this.integrityAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.creationDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
			this.lastModifiedDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
			this.objectDataSequence = ObjectDataSequence.getInstance(seq.getObjectAt(4));
			this.comment = (seq.size() == 6) ? DERUTF8String.getInstance(seq.getObjectAt(5)).getString() : null;
		}

		public static ObjectStoreData getInstance(object o)
		{
			if (o is ObjectStoreData)
			{
				return (ObjectStoreData)o;
			}
			else if (o != null)
			{
				return new ObjectStoreData(ASN1Sequence.getInstance(o));
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

		public virtual AlgorithmIdentifier getIntegrityAlgorithm()
		{
			return integrityAlgorithm;
		}

		public virtual ASN1GeneralizedTime getLastModifiedDate()
		{
			return lastModifiedDate;
		}

		public virtual ObjectDataSequence getObjectDataSequence()
		{
			return objectDataSequence;
		}

		public virtual BigInteger getVersion()
		{
			return version;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(version));
			v.add(integrityAlgorithm);
			v.add(creationDate);
			v.add(lastModifiedDate);
			v.add(objectDataSequence);

			if (!string.ReferenceEquals(comment, null))
			{
				v.add(new DERUTF8String(comment));
			}

			return new DERSequence(v);
		}
	}

}