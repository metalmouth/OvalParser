import glob
from bs4 import BeautifulSoup
import codecs
import requests
import xlsxwriter
from deep_translator import GoogleTranslator
from itertools import chain



TABLE_HEAD = [
    "№",
    "BDU",
    "CWE",
    "CAPEC High",
    "CAPEC Medium",
    "CAPEC Low",
    "No chance"
]


st_accept = "text/html" # говорим веб-серверу, 
                        # что хотим получить html
# имитируем подключение через браузер Mozilla на macOS
st_useragent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15"
# формируем хеш заголовков
headers = {
   "Accept": st_accept,
   "User-Agent": st_useragent
}



def find(s, ch): # находит все индексы элемента строки
    return [i for i, ltr in enumerate(s) if (ltr == ch and i != 0)]

def insert_newlines(s, indices):
    # Сортируем индексы в обратном порядке, чтобы вставка не влияла на последующие индексы
    for index in sorted(indices, reverse=True):
        s = s[:index] + '\n' + s[index:]
    return s


def split_string_by_indices(s, indices):
    # Добавляем начальный и конечный индексы для удобства
    indices = sorted(indices)
    result = []
    start = 0

    for index in indices:
        # Добавляем подстроку от start до index
        result.append(s[start:index])
        start = index

    # Добавляем оставшуюся часть строки
    result.append(s[start:])

    return result



try:
    files = glob.glob("*Oval*")
except:
    print("Files not found")
    exit(1)

for file in files:

    c = 1

    rowT = 0
    colT = 0
    rowCapec = 0


    cwe_cache = {}

    try:

        workbook = xlsxwriter.Workbook('ParserResult.xlsx')
        worksheet = workbook.add_worksheet("MAIN_TABLE")
        worksheet_bdu = workbook.add_worksheet("BDU_DESC")
        worksheet_capec = workbook.add_worksheet("CAPEC_DESC")
    except:
        print("Cannot open Excel file")
        exit(1)

    for k, word in enumerate(TABLE_HEAD):
        worksheet.write(rowT, colT + k, word)
    rowT += 1

    print(f"File found: {file}")

    file = codecs.open( file, "r", "utf-8" )
    data = file.read()
    soup = BeautifulSoup(data,"html.parser")

    all_bdu = soup.find_all('td', {'class': 'font10pt title key'})
    l_bdu = len(all_bdu)


    for i in all_bdu:
        bdu = i.get_text()
        if bdu.count("BDU") > 1:
            bdu = split_string_by_indices(bdu, find(bdu,"B"))

        if not isinstance(bdu, list): bdu = [bdu]



        for i in bdu:

            print(f"Parsing {i}...", end=" ", flush=True)

            capec_low, capec_medium, capec_high, capec_no_chance = [], [], [], []


            worksheet.write(rowT, TABLE_HEAD.index("№"), c)
            worksheet.write(rowT, TABLE_HEAD.index("BDU"), i)

            

            response = requests.get("https://service.securitm.ru/vm/vulnerability/fstec/show/" + i)
            soup = BeautifulSoup(response.text, 'html.parser')

            bdu_desc = soup.find('div', class_='text-justify mb-2').text

            worksheet_bdu.write(rowT, 0, rowT)
            worksheet_bdu.write(rowT, 1, i)
            worksheet_bdu.write(rowT, 2, bdu_desc)


            card_body = soup.find('div', class_='card-body border-top-0')

            # Если блок найден, ищем таблицу
            if card_body:
                table = card_body.find('table', class_='table table-sm table-striped table-bordered')

                # Если таблица найдена, извлекаем данные
                if table:
                    cwe_list = []
                    rows = table.find_all('tr')  # Находим все строки таблицы

                    for row in rows:
                        cells = row.find_all('td')  # Находим все ячейки в строке
                        if len(cells) == 2:  # Проверяем, что строка содержит две ячейки
                            cwe_id = cells[0].text.strip()  # Идентификатор CWE

                            cwe_list.append(cwe_id)



                    worksheet.write(rowT, TABLE_HEAD.index("CWE"), ",".join(cwe_list))
                                        # Выводим результат
                    for cwe in cwe_list:
                        
                        if cwe not in cwe_cache:
                            print(f"{cwe} is not cached.", end=" ", flush=True)
                            cwe_cache[cwe] = {}
                            cwe_cache[cwe]["capec_high"] = list()
                            cwe_cache[cwe]["capec_medium"] = list()
                            cwe_cache[cwe]["capec_low"] = list()
                            cwe_cache[cwe]["capec_no_chance"] = list()


                            cwe_response = requests.get("https://cwe.mitre.org/data/definitions/" + cwe[4:] + ".html")
                            soup = BeautifulSoup(cwe_response.text, 'html.parser')


                            cwe_body = soup.find('div', id='Related_Attack_Patterns')
                            if cwe_body:
                                cwe_table = cwe_body.find('table', class_='Detail')
                                if cwe_table:
                                    cwe_a = cwe_table.find_all('a', href=True)
                                    for a in cwe_a:
                                        if a.text not in chain(capec_high, capec_medium, capec_low, capec_no_chance):
                                            worksheet_capec.write(rowCapec, 0, rowCapec + 1)
                                            worksheet_capec.write(rowCapec, 1, a.text)

                                            response = requests.get(a['href'])
                                            soup = BeautifulSoup(response.text, 'html.parser')

                                            capec_desc = soup.find('div', id='Description')
                                            if capec_desc:
                                                capec_text = capec_desc.find('div', class_='indent').text
                                                worksheet_capec.write(rowCapec, 2, capec_text)
                                                worksheet_capec.write(rowCapec, 3, GoogleTranslator(source='en', target='ru').translate(capec_text))
                                                
                                            rowCapec += 1

                                        capec_body = soup.find('div', id='Likelihood_Of_Attack')
                                        if capec_body:
                                            likehood = capec_body.find('p').text
                                            if likehood == "High":
                                                cwe_cache[cwe]["capec_high"].append(a.text)
                                            elif likehood == "Medium":
                                                cwe_cache[cwe]["capec_medium"].append(a.text)
                                            else:
                                                cwe_cache[cwe]["capec_low"].append(a.text)
                                        else:
                                            cwe_cache[cwe]["capec_no_chance"].append(a.text)


                    worksheet.write(rowT, TABLE_HEAD.index("CAPEC High"), ", ".join(cwe_cache[cwe]["capec_high"]))
                    worksheet.write(rowT, TABLE_HEAD.index("CAPEC Medium"), ", ".join(cwe_cache[cwe]["capec_medium"]))
                    worksheet.write(rowT, TABLE_HEAD.index("CAPEC Low"), ", ".join(cwe_cache[cwe]["capec_low"]))
                    worksheet.write(rowT, TABLE_HEAD.index("No chance"), ", ".join(cwe_cache[cwe]["capec_no_chance"]))

            print("OK") 
            print(f"Parsed {c} of {l_bdu} BDU's")      
            rowT += 1
            c += 1

                    
        

try:
    workbook.close()
except:
    print("Excel file exception")
    exit(1)
