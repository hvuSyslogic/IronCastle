using System.IO;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.eac
{

	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// an Iso7816CertificateHolderAuthorization structure.
	/// <pre>
	///  Certificate Holder Authorization ::= SEQUENCE {
	///      // specifies the format and the rules for the evaluation of the authorization
	///      // level
	///      ASN1ObjectIdentifier        oid,
	///      // access rights
	///      DERApplicationSpecific    accessRights,
	///  }
	/// </pre>
	/// </summary>
	public class CertificateHolderAuthorization : ASN1Object
	{
		internal ASN1ObjectIdentifier oid;
		internal ASN1ApplicationSpecific accessRights;
		public static readonly ASN1ObjectIdentifier id_role_EAC = EACObjectIdentifiers_Fields.bsi_de.branch("3.1.2.1");
		public const int CVCA = 0xC0;
		public const int DV_DOMESTIC = 0x80;
		public const int DV_FOREIGN = 0x40;
		public const int IS = 0;
		public const int RADG4 = 0x02; //Read Access to DG4 (Iris)
		public const int RADG3 = 0x01; //Read Access to DG3 (fingerprint)

		internal static Hashtable RightsDecodeMap = new Hashtable();
		internal static BidirectionalMap AuthorizationRole = new BidirectionalMap();
		internal static Hashtable ReverseMap = new Hashtable();

		static CertificateHolderAuthorization()
		{
			RightsDecodeMap.put(Integers.valueOf(RADG4), "RADG4");
			RightsDecodeMap.put(Integers.valueOf(RADG3), "RADG3");

			AuthorizationRole.put(Integers.valueOf(CVCA), "CVCA");
			AuthorizationRole.put(Integers.valueOf(DV_DOMESTIC), "DV_DOMESTIC");
			AuthorizationRole.put(Integers.valueOf(DV_FOREIGN), "DV_FOREIGN");
			AuthorizationRole.put(Integers.valueOf(IS), "IS");

			/*
			  for (int i : RightsDecodeMap.keySet())
			      ReverseMap.put(RightsDecodeMap.get(i), i);
	
			  for (int i : AuthorizationRole.keySet())
			      ReverseMap.put(AuthorizationRole.get(i), i);
			  */
		}

		public static string getRoleDescription(int i)
		{
			return (string)AuthorizationRole.get(Integers.valueOf(i));
		}

		public static int getFlag(string description)
		{
			int? i = (int?)AuthorizationRole.getReverse(description);
			if (i == null)
			{
				throw new IllegalArgumentException("Unknown value " + description);
			}

			return i.Value;
		}

		private void setPrivateData(ASN1InputStream cha)
		{
			ASN1Primitive obj;
			obj = cha.readObject();
			if (obj is ASN1ObjectIdentifier)
			{
				this.oid = (ASN1ObjectIdentifier)obj;
			}
			else
			{
				throw new IllegalArgumentException("no Oid in CerticateHolderAuthorization");
			}
			obj = cha.readObject();
			if (obj is ASN1ApplicationSpecific)
			{
				this.accessRights = (ASN1ApplicationSpecific)obj;
			}
			else
			{
				throw new IllegalArgumentException("No access rights in CerticateHolderAuthorization");
			}
		}


		/// <summary>
		/// create an Iso7816CertificateHolderAuthorization according to the parameters
		/// </summary>
		/// <param name="oid">    Object Identifier : specifies the format and the rules for the
		///               evaluatioin of the authorization level. </param>
		/// <param name="rights"> specifies the access rights </param>
		/// <exception cref="IOException"> </exception>
		public CertificateHolderAuthorization(ASN1ObjectIdentifier oid, int rights)
		{
			setOid(oid);
			setAccessRights((byte)rights);
		}

		/// <summary>
		/// create an Iso7816CertificateHolderAuthorization according to the <seealso cref="ASN1ApplicationSpecific"/>
		/// </summary>
		/// <param name="aSpe"> the DERApplicationSpecific containing the data </param>
		/// <exception cref="IOException"> </exception>
		public CertificateHolderAuthorization(ASN1ApplicationSpecific aSpe)
		{
			if (aSpe.getApplicationTag() == EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE)
			{
				setPrivateData(new ASN1InputStream(aSpe.getContents()));
			}
		}

		/// <returns> containing the access rights </returns>
		public virtual int getAccessRights()
		{
			return accessRights.getContents()[0] & 0xff;
		}

		/// <summary>
		/// create a DERApplicationSpecific and set the access rights to "rights"
		/// </summary>
		/// <param name="rights"> byte containing the rights. </param>
		private void setAccessRights(byte rights)
		{
			byte[] accessRights = new byte[1];
			accessRights[0] = rights;
			this.accessRights = new DERApplicationSpecific(EACTags.DISCRETIONARY_DATA, accessRights);
		}

		/// <returns> the Object identifier </returns>
		public virtual ASN1ObjectIdentifier getOid()
		{
			return oid;
		}

		/// <summary>
		/// set the Object Identifier
		/// </summary>
		/// <param name="oid"> <seealso cref="ASN1ObjectIdentifier"/> containing the Object Identifier </param>
		private void setOid(ASN1ObjectIdentifier oid)
		{
			this.oid = oid;
		}

		/// <summary>
		/// return the Certificate Holder Authorization as a DERApplicationSpecific Object
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(oid);
			v.add(accessRights);

			return new DERApplicationSpecific(EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE, v);
		}
	}

}