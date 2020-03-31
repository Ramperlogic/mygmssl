package mygmssl;

public class SM4_Context {
	public int mode;			//模式
	public long[] sk;			//
	public boolean isPadding;	//填充
	public SM4_Context()
    {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
