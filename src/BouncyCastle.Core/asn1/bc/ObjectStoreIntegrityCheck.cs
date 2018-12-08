using System.IO;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.bc
{


	/// <summary>
	/// <pre>
	/// ObjectStoreIntegrityCheck ::= CHOICE {
	///     PbeMacIntegrityCheck
	/// }
	/// </pre>
	/// </summary>
	public class ObjectStoreIntegrityCheck : ASN1Object, ASN1Choice
	{
		public const int PBKD_MAC_CHECK = 0;

		private readonly int type;
		private readonly ASN1Object integrityCheck;

		public ObjectStoreIntegrityCheck(PbkdMacIntegrityCheck macIntegrityCheck) : this((ASN1Encodable)macIntegrityCheck)
		{
		}

		private ObjectStoreIntegrityCheck(ASN1Encodable obj)
		{
			if (obj is ASN1Sequence || obj is PbkdMacIntegrityCheck)
			{
				this.type = PBKD_MAC_CHECK;
				this.integrityCheck = PbkdMacIntegrityCheck.getInstance(obj);
			}
			else
			{
				throw new IllegalArgumentException("Unknown check object in integrity check.");
			}
		}

		public static ObjectStoreIntegrityCheck getInstance(object o)
		{
			if (o is ObjectStoreIntegrityCheck)
			{
				return (ObjectStoreIntegrityCheck)o;
			}
			else if (o is byte[])
			{
				try
				{
					return new ObjectStoreIntegrityCheck(ASN1Primitive.fromByteArray((byte[])o));
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("Unable to parse integrity check details.");
				}
			}
			else if (o != null)
			{
				return new ObjectStoreIntegrityCheck((ASN1Encodable)(o));
			}

			return null;
		}


		public virtual int getType()
		{
			return type;
		}

		public virtual ASN1Object getIntegrityCheck()
		{
			return integrityCheck;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return integrityCheck.toASN1Primitive();
		}
	}

}