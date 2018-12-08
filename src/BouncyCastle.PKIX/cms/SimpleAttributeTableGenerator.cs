namespace org.bouncycastle.cms
{
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;

	/// <summary>
	/// Basic generator that just returns a preconstructed attribute table
	/// </summary>
	public class SimpleAttributeTableGenerator : CMSAttributeTableGenerator
	{
		private readonly AttributeTable attributes;

		public SimpleAttributeTableGenerator(AttributeTable attributes)
		{
			this.attributes = attributes;
		}

		public virtual AttributeTable getAttributes(Map parameters)
		{
			return attributes;
		}
	}

}