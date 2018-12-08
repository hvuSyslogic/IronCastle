namespace org.bouncycastle.crypto.tls
{
	public class SupplementalDataEntry
	{
		protected internal int dataType;
		protected internal byte[] data;

		public SupplementalDataEntry(int dataType, byte[] data)
		{
			this.dataType = dataType;
			this.data = data;
		}

		public virtual int getDataType()
		{
			return dataType;
		}

		public virtual byte[] getData()
		{
			return data;
		}
	}

}