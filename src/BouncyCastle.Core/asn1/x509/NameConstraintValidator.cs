namespace org.bouncycastle.asn1.x509
{
	public interface NameConstraintValidator
	{
		void checkPermitted(GeneralName name);

		void checkExcluded(GeneralName name);

		void intersectPermittedSubtree(GeneralSubtree permitted);

		void intersectPermittedSubtree(GeneralSubtree[] permitted);

		void intersectEmptyPermittedSubtree(int nameType);

		void addExcludedSubtree(GeneralSubtree subtree);
	}

}