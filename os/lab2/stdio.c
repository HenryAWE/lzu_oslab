#include <stdio.h>
#include <kdebug.h>
#include <stdarg.h>


//stdarg.h����ı����ͺ꣺
//va_list
//������ va_start()��va_arg() �� va_end() ��������洢��Ϣ������

//va_start(ap, param)
//va_arg(ap, type)
//va_end(ap)
//va_copy(dest, src)*Linux�õ���C��׼����

//va_list�ַ�ָ�룬ָ��ǰ������ȡ�α���ͨ�����ָ����С�
//va_start(ap, last_arg)��ap���г�ʼ�������ڻ�ȡ�����б��пɱ��������ָ��
//ap���ڱ��溯�������б��пɱ��������ָ��(��,�ɱ�����б�)
//last_argΪ���������б������һ���̶�����

//va_arg(ap, type)���ڻ�ȡ��ǰap��ָ�Ŀɱ������������apָ��������һ�ɱ����
//�������ap(����Ϊva_list) : �ɱ�����б�ָ��ǰ��Ҫ����Ŀɱ����
//�������type : ��Ҫ����Ŀɱ����������
//����ֵ : ��ǰ�ɱ������ֵ,��һ������Ϊ type �ı��ʽ.

//va_end(ap)���ڽ����Կɱ�����Ĵ���
//ʵ����, va_end������Ϊ��.��ֻ��Ϊʵ����va_start���(ʵ�ִ���Գƺ�"������ע��"����)

static unsigned long kpow(int x, int y);
int kprintf(const char *_Format, ...);

int kprintf(const char *_Format, ...) {
	va_list ap;		//����ɱ��������ָ��
	int val;		//decimal value
	int temp;		//medium value ��decimal to char��
	char len;		//decimal length
	int rev = 0;	//return value:length of string
	int ch;			//character
	int* str = NULL;//string


	va_start(ap, _Format);
	while (*_Format != '\0')
	{
		switch (*_Format)
		{
		case '%':
			_Format++;
			switch (*_Format)
			{
			case 'd':		//Decimal
				val = va_arg(ap, int);
				temp = val;
				len = 0;
				while (temp)
				{
					len++;
					temp /= 10;
				}
				rev += len;
				temp = val;
				while (len)
				{
					ch = temp / kpow(10, len - 1);
					temp %= kpow(10, len - 1);
					kputchar(ch + '0');				//kputchar������תΪ�ַ����
					len--;
				}
				break;
			
			case 'x':
				CaseX:
				val = va_arg(ap, int);
				temp = val;
				len = 0;
				while (temp)
				{
					len++;
					temp /= 16;
				}
				rev += len;
				temp = val;
				while (len)
				{
					ch = temp / kpow(16, len - 1);
					temp %= kpow(16, len - 1);
					if (ch <= 9)
					{
						kputchar(ch + '0');
					}
					else
					{
						kputchar(ch - 10 + 'a');
					}
					len--;
				}
				break;
			case 'p':
				kputchar('0');
				kputchar('x');
				goto CaseX;
				break;
			case 's':		//string
				str = va_arg(ap, int *);
				while (str)
				{
					kputchar(str);
					str++;
				}
				rev = sizeof(str) - 1;
				break;
			case 'c':		//character
				kputchar(va_arg(ap, int));
				rev += 1;
				break;
			default:
				break;
			}
		case '\n':
			kputchar('\n');
			break;
		case '\r':
			kputchar('\r');
			break;
		case '\t':
			kputchar('\t');
			break;
		default:
			kputchar(*_Format);
		}
		_Format++;
	}
	va_end(ap);
	//return rev;
}

static unsigned long kpow(int x, int y) {
	unsigned long sum = 1;
	while (y--)
	{
		sum *= x;
	}
	return sum;
}

//TEST:
//int main() {
//	int a = 22;
//	char* p = "abc";
//	kprintf("%c%d",'c', 11);
//	kprintf("%x\r", a);
//	kprintf("%p", p);
//	kprintf("%s", 'hi');
//	/*string����*/
//}