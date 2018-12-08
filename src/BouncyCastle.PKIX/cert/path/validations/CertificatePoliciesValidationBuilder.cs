namespace org.bouncycastle.cert.path.validations
{

	public class CertificatePoliciesValidationBuilder
	{
		private bool isExplicitPolicyRequired;
		private bool isAnyPolicyInhibited;
		private bool isPolicyMappingInhibited;

		public virtual void setAnyPolicyInhibited(bool anyPolicyInhibited)
		{
			isAnyPolicyInhibited = anyPolicyInhibited;
		}

		public virtual void setExplicitPolicyRequired(bool explicitPolicyRequired)
		{
			isExplicitPolicyRequired = explicitPolicyRequired;
		}

		public virtual void setPolicyMappingInhibited(bool policyMappingInhibited)
		{
			isPolicyMappingInhibited = policyMappingInhibited;
		}

		public virtual CertificatePoliciesValidation build(int pathLen)
		{
			return new CertificatePoliciesValidation(pathLen, isExplicitPolicyRequired, isAnyPolicyInhibited, isPolicyMappingInhibited);
		}

		public virtual CertificatePoliciesValidation build(CertPath path)
		{
			return build(path.length());
		}
	}

}