using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.dvcs
{



	/// <summary>
	/// ServiceType ::= ENUMERATED { cpd(1), vsd(2), cpkc(3), ccpd(4) }
	/// </summary>

	public class ServiceType : ASN1Object
	{
		/// <summary>
		/// Identifier of CPD service (Certify Possession of Data).
		/// </summary>
		public static readonly ServiceType CPD = new ServiceType(1);

		/// <summary>
		/// Identifier of VSD service (Verify Signed Document).
		/// </summary>
		public static readonly ServiceType VSD = new ServiceType(2);

		/// <summary>
		/// Identifier of VPKC service (Verify Public Key Certificates (also referred to as CPKC)).
		/// </summary>
		public static readonly ServiceType VPKC = new ServiceType(3);

		/// <summary>
		/// Identifier of CCPD service (Certify Claim of Possession of Data).
		/// </summary>
		public static readonly ServiceType CCPD = new ServiceType(4);

		private ASN1Enumerated value;

		public ServiceType(int value)
		{
			this.value = new ASN1Enumerated(value);
		}

		private ServiceType(ASN1Enumerated value)
		{
			this.value = value;
		}

		public static ServiceType getInstance(object obj)
		{
			if (obj is ServiceType)
			{
				return (ServiceType)obj;
			}
			else if (obj != null)
			{
				return new ServiceType(ASN1Enumerated.getInstance(obj));
			}

			return null;
		}

		public static ServiceType getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Enumerated.getInstance(obj, @explicit));
		}

		public virtual BigInteger getValue()
		{
			return value.getValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return value;
		}

		public override string ToString()
		{
			int num = value.getValue().intValue();
			return "" + num + (num == CPD.getValue().intValue() ? "(CPD)" : num == VSD.getValue().intValue() ? "(VSD)" : num == VPKC.getValue().intValue() ? "(VPKC)" : num == CCPD.getValue().intValue() ? "(CCPD)" : "?");
		}

	}

}