using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.cmp
{


	public class PKIStatus : ASN1Object
	{
		public const int GRANTED = 0;
		public const int GRANTED_WITH_MODS = 1;
		public const int REJECTION = 2;
		public const int WAITING = 3;
		public const int REVOCATION_WARNING = 4;
		public const int REVOCATION_NOTIFICATION = 5;
		public const int KEY_UPDATE_WARNING = 6;

		public static readonly PKIStatus granted = new PKIStatus(GRANTED);
		public static readonly PKIStatus grantedWithMods = new PKIStatus(GRANTED_WITH_MODS);
		public static readonly PKIStatus rejection = new PKIStatus(REJECTION);
		public static readonly PKIStatus waiting = new PKIStatus(WAITING);
		public static readonly PKIStatus revocationWarning = new PKIStatus(REVOCATION_WARNING);
		public static readonly PKIStatus revocationNotification = new PKIStatus(REVOCATION_NOTIFICATION);
		public static readonly PKIStatus keyUpdateWaiting = new PKIStatus(KEY_UPDATE_WARNING);

		private ASN1Integer value;

		private PKIStatus(int value) : this(new ASN1Integer(value))
		{
		}

		private PKIStatus(ASN1Integer value)
		{
			this.value = value;
		}

		public static PKIStatus getInstance(object o)
		{
			if (o is PKIStatus)
			{
				return (PKIStatus)o;
			}

			if (o != null)
			{
				return new PKIStatus(ASN1Integer.getInstance(o));
			}

			return null;
		}

		public virtual BigInteger getValue()
		{
			return value.getValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return value;
		}
	}

}