using System;

namespace org.bouncycastle.est
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using AttrOrOID = org.bouncycastle.asn1.est.AttrOrOID;
	using CsrAttrs = org.bouncycastle.asn1.est.CsrAttrs;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Wrapper class around a CsrAttrs structure.
	/// </summary>
	public class CSRAttributesResponse : Encodable
	{
		private readonly CsrAttrs csrAttrs;
		private readonly HashMap<ASN1ObjectIdentifier, AttrOrOID> index;

		/// <summary>
		/// Create a CSRAttributesResponse from the passed in bytes.
		/// </summary>
		/// <param name="responseEncoding"> BER/DER encoding of the certificate. </param>
		/// <exception cref="ESTException"> in the event of corrupted data, or an incorrect structure. </exception>
		public CSRAttributesResponse(byte[] responseEncoding) : this(parseBytes(responseEncoding))
		{
		}

		/// <summary>
		/// Create a CSRAttributesResponse from the passed in ASN.1 structure.
		/// </summary>
		/// <param name="csrAttrs"> an RFC 7030 CsrAttrs structure. </param>
		public CSRAttributesResponse(CsrAttrs csrAttrs)
		{
			this.csrAttrs = csrAttrs;
			this.index = new HashMap<ASN1ObjectIdentifier, AttrOrOID>(csrAttrs.size());

			AttrOrOID[] attrOrOIDs = csrAttrs.getAttrOrOIDs();
			for (int i = 0; i != attrOrOIDs.Length; i++)
			{
				AttrOrOID attrOrOID = attrOrOIDs[i];

				if (attrOrOID.isOid())
				{
					index.put(attrOrOID.getOid(), attrOrOID);
				}
				else
				{
					index.put(attrOrOID.getAttribute().getAttrType(), attrOrOID);
				}
			}
		}

		private static CsrAttrs parseBytes(byte[] responseEncoding)
		{
			try
			{
				return CsrAttrs.getInstance(ASN1Primitive.fromByteArray(responseEncoding));
			}
			catch (Exception e)
			{
				throw new ESTException("malformed data: " + e.Message, e);
			}
		}

		public virtual bool hasRequirement(ASN1ObjectIdentifier requirementOid)
		{
			return index.containsKey(requirementOid);
		}

		public virtual bool isAttribute(ASN1ObjectIdentifier requirementOid)
		{
			if (index.containsKey(requirementOid))
			{
				return !(((AttrOrOID)index.get(requirementOid)).isOid());
			}

			return false;
		}

		public virtual bool isEmpty()
		{
			return csrAttrs.size() == 0;
		}

		public virtual Collection<ASN1ObjectIdentifier> getRequirements()
		{
			return index.keySet();
		}

		public virtual byte[] getEncoded()
		{
			return csrAttrs.getEncoded();
		}
	}

}