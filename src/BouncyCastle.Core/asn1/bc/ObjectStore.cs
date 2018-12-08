using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.bc
{

	/// <summary>
	/// <pre>
	/// ObjectStore ::= SEQUENCE {
	///     CHOICE {
	///          encryptedObjectStoreData EncryptedObjectStoreData,
	///          objectStoreData ObjectStoreData
	///     }
	///     integrityCheck ObjectStoreIntegrityCheck
	/// }
	/// </pre>
	/// </summary>
	public class ObjectStore : ASN1Object
	{
		private readonly ASN1Encodable storeData;
		private readonly ObjectStoreIntegrityCheck integrityCheck;

		public ObjectStore(ObjectStoreData objectStoreData, ObjectStoreIntegrityCheck integrityCheck)
		{
			this.storeData = objectStoreData;
			this.integrityCheck = integrityCheck;
		}


		public ObjectStore(EncryptedObjectStoreData encryptedObjectStoreData, ObjectStoreIntegrityCheck integrityCheck)
		{
			this.storeData = encryptedObjectStoreData;
			this.integrityCheck = integrityCheck;
		}

		private ObjectStore(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("malformed sequence");
			}

			ASN1Encodable sData = seq.getObjectAt(0);
			if (sData is EncryptedObjectStoreData)
			{
				this.storeData = sData;
			}
			else if (sData is ObjectStoreData)
			{
				this.storeData = sData;
			}
			else
			{
				ASN1Sequence seqData = ASN1Sequence.getInstance(sData);

				if (seqData.size() == 2)
				{
					this.storeData = EncryptedObjectStoreData.getInstance(seqData);
				}
				else
				{
					this.storeData = ObjectStoreData.getInstance(seqData);
				}
			}

			this.integrityCheck = ObjectStoreIntegrityCheck.getInstance(seq.getObjectAt(1));
		}

		public static ObjectStore getInstance(object o)
		{
			if (o is ObjectStore)
			{
				return (ObjectStore)o;
			}
			else if (o != null)
			{
				return new ObjectStore(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual ObjectStoreIntegrityCheck getIntegrityCheck()
		{
			return integrityCheck;
		}

		public virtual ASN1Encodable getStoreData()
		{
			return storeData;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(storeData);
			v.add(integrityCheck);

			return new DERSequence(v);
		}
	}

}