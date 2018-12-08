namespace org.bouncycastle.cms
{
	/// <summary>
	/// General class for generating a CMS encrypted-data message.
	/// </summary>
	public class CMSEncryptedGenerator
	{
		protected internal CMSAttributeTableGenerator unprotectedAttributeGenerator = null;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSEncryptedGenerator()
		{
		}

		public virtual void setUnprotectedAttributeGenerator(CMSAttributeTableGenerator unprotectedAttributeGenerator)
		{
			this.unprotectedAttributeGenerator = unprotectedAttributeGenerator;
		}
	}

}