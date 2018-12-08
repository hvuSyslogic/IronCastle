using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// Policy qualifiers, used in the X509V3 CertificatePolicies
	/// extension.
	/// 
	/// <pre>
	///   PolicyQualifierInfo ::= SEQUENCE {
	///       policyQualifierId  PolicyQualifierId,
	///       qualifier          ANY DEFINED BY policyQualifierId }
	/// 
	///  PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
	/// </pre>
	/// </summary>
	public class PolicyQualifierInfo : ASN1Object
	{
	   private ASN1ObjectIdentifier policyQualifierId;
	   private ASN1Encodable qualifier;

	   /// <summary>
	   /// Creates a new <code>PolicyQualifierInfo</code> instance.
	   /// </summary>
	   /// <param name="policyQualifierId"> a <code>PolicyQualifierId</code> value </param>
	   /// <param name="qualifier"> the qualifier, defined by the above field. </param>
	   public PolicyQualifierInfo(ASN1ObjectIdentifier policyQualifierId, ASN1Encodable qualifier)
	   {
		  this.policyQualifierId = policyQualifierId;
		  this.qualifier = qualifier;
	   }

	   /// <summary>
	   /// Creates a new <code>PolicyQualifierInfo</code> containing a
	   /// cPSuri qualifier.
	   /// </summary>
	   /// <param name="cps"> the CPS (certification practice statement) uri as a
	   /// <code>String</code>. </param>
	   public PolicyQualifierInfo(string cps)
	   {
		  policyQualifierId = PolicyQualifierId.id_qt_cps;
		  qualifier = new DERIA5String(cps);
	   }

	   /// <summary>
	   /// Creates a new <code>PolicyQualifierInfo</code> instance.
	   /// </summary>
	   /// <param name="as"> <code>PolicyQualifierInfo</code> X509 structure
	   /// encoded as an ASN1Sequence. </param>
	   /// @deprecated use PolicyQualifierInfo.getInstance() 
	   public PolicyQualifierInfo(ASN1Sequence @as)
	   {
			if (@as.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + @as.size());
			}

			policyQualifierId = ASN1ObjectIdentifier.getInstance(@as.getObjectAt(0));
			qualifier = @as.getObjectAt(1);
	   }

	   public static PolicyQualifierInfo getInstance(object obj)
	   {
			if (obj is PolicyQualifierInfo)
			{
				return (PolicyQualifierInfo)obj;
			}
			else if (obj != null)
			{
				return new PolicyQualifierInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
	   }


	   public virtual ASN1ObjectIdentifier getPolicyQualifierId()
	   {
		   return policyQualifierId;
	   }

	   public virtual ASN1Encodable getQualifier()
	   {
		   return qualifier;
	   }

	   /// <summary>
	   /// Returns a DER-encodable representation of this instance. 
	   /// </summary>
	   /// <returns> a <code>ASN1Primitive</code> value </returns>
	   public override ASN1Primitive toASN1Primitive()
	   {
		  ASN1EncodableVector dev = new ASN1EncodableVector();
		  dev.add(policyQualifierId);
		  dev.add(qualifier);

		  return new DERSequence(dev);
	   }
	}

}