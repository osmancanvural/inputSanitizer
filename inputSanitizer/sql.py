import re

def sqlSanitize(girdi: str, mod: int = 1) -> str:
    # Mod 0: sadece rakam kabul et. numeric parametre kullanan sorgular icin kullanilir
    if mod == 0:
        return re.sub(r'[^0-9]', '', girdi)
    
    # Mod 1: SQL injectiona sebep olabilecek ozel karakterleri temizle. default mod
    elif mod == 1:
        ozel_karakterler = r"[\'\";\\\-–—#/*()|=+]"
        return re.sub(ozel_karakterler, '', girdi)
    
    # Mod 2: Sql'de anlam ifade eden tum keywordleri ve ozel karakterleri temizle. (cok fazla false positive'e sebep olabilir)
    elif mod == 2:
        special_chars_pattern = r"[\'\";\\\-–—#/*()|=+]"
        
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'truncate',
            'grant', 'revoke', 'union', 'and', 'or', 'not', 'like', 'where', 'from', 'table',
            'database', 'schema', 'procedure', 'function', 'exec', 'execute', 'fetch', 'declare',
            'cursor', 'begin', 'end', 'transaction', 'commit', 'rollback', 'having', 'group by',
            'order by', 'limit', 'offset', 'into', 'values', 'set', 'join', 'inner', 'outer',
            'left', 'right', 'full', 'cross', 'natural', 'using', 'on', 'exists', 'in', 'any',
            'all', 'some', 'between', 'is', 'null', 'not null', 'case', 'when', 'then', 'else',
            'end', 'as', 'distinct', 'with', 'recursive', 'window', 'over', 'partition', 'by',
            'rows', 'range', 'preceding', 'following', 'current', 'row', 'first', 'last', 'lead',
            'lag', 'percent', 'rank', 'dense_rank', 'percent_rank', 'cume_dist', 'ntile', 'xml',
            'json', 'array', 'rowset', 'pivot', 'unpivot', 'for', 'path', 'escape', 'collate', 'cast',
            'convert', 'try_cast', 'try_convert', 'parse', 'try_parse', 'iif', 'choose', 'concat',
            'coalesce', 'nullif', 'isnull', 'isnumeric', 'isdate', 'isjson', 'session_user', 
            'system_user', 'current_user', 'user_name', 'schema_name', 'database_name', 'object_name',
            'column_name', 'index_name', 'constraint_name', 'trigger_name', 'view_name', 'procedure_name',
            'function_name', 'parameter_name', 'type_name', 'assembly_name', 'file_name', 'login_name',
            'server_name', 'service_name', 'queue_name', 'contract_name', 'message_type_name', 'route_name',
            'remote_service_name', 'fulltext_catalog_name', 'fulltext_stoplist_name', 'search_property_list_name',
            'certificate_name', 'symmetric_key_name', 'asymmetric_key_name', 'credential_name', 'cryptographic_provider_name',
            'audit_name', 'audit_specification_name', 'server_audit_specification_name', 'database_audit_specification_name',
            'endpoint_name', 'event_notification_name', 'linked_server_name', 'login_token', 'master_key', 'password',
            'principal', 'role', 'schema', 'sequence', 'server_role', 'service_broker', 'signature', 'statistics',
            'symmetric_key', 'synonym', 'user', 'workload_group', 'xml_schema_collection', 'application_role', 'assembly',
            'availability_group', 'certificate', 'contract', 'credential', 'cryptographic_provider', 'database', 'database_role',
            'endpoint', 'event_notification', 'event_session', 'extended_procedure', 'external_data_source', 'external_file_format',
            'external_library', 'external_resource_pool', 'external_table', 'fulltext_catalog', 'fulltext_index', 'fulltext_stoplist',
            'linked_server', 'login', 'master_key', 'message_type', 'partition_function', 'partition_scheme', 'queue',
            'remote_service_binding', 'resource_governor', 'resource_pool', 'route', 'rule', 'schema', 'search_property_list',
            'security_policy', 'security_predicate', 'sequence', 'server', 'server_role', 'service', 'signature', 'statistics',
            'symmetric_key', 'synonym', 'table', 'trigger', 'type', 'user', 'view', 'workload_group', 'xml_schema_collection',
            'column', 'constraint', 'index', 'parameter', 'trigger', 'variable', 'waitfor', 'delay', 'time', 'kill', 'shutdown',
            'backup', 'restore', 'reconfigure', 'checkpoint', 'dbcc', 'deny', 'revoke', 'revert', 'open', 'close', 'deallocate',
            'fetch', 'read', 'write', 'holdlock', 'nolock', 'paglock', 'readcommitted', 'readpast', 'repeatableread', 'rowlock',
            'serializable', 'tablock', 'tablockx', 'updlock', 'xact_abort', 'implicit_transactions', 'remote_proc_transactions',
            'save', 'tran', 'transaction', 'begin', 'commit', 'rollback', 'set', 'go', 'use', 'waitfor', 'while', 'break',
            'continue', 'goto', 'return', 'try', 'catch', 'throw', 'raiserror', 'print', 'execute', 'sp_executesql', 'xp_',
            'sp_', 'sys.', 'information_schema.', 'fn_', 'dm_', 'msdb.', 'tempdb.', 'model.', 'master.', 'resource.', 'openquery',
            'opendatasource', 'openrowset', 'bulk', 'insert', 'update', 'delete', 'merge', 'output', 'into', 'default', 'null',
            'identity', 'constraint', 'primary', 'key', 'foreign', 'references', 'check', 'unique', 'index', 'cluster', 'noncluster',
            'statistics', 'with', 'option', 'fastfirstrow', 'force', 'holdlock', 'maxdop', 'optimize', 'keep', 'plan', 'keepfixed',
            'expand', 'views', 'maxrecursion', 'recompile', 'robust', 'plan', 'simple', 'view_metadata', 'xml', 'binary', 'base64',
            'path', 'auto', 'explicit', 'raw', 'array', 'object', 'abs', 'acos', 'asin', 'atan', 'atn2', 'ceiling', 'cos', 'cot',
            'degrees', 'exp', 'floor', 'log', 'log10', 'pi', 'power', 'radians', 'rand', 'round', 'sign', 'sin', 'sqrt', 'square',
            'tan', 'ascii', 'char', 'charindex', 'concat', 'difference', 'format', 'left', 'len', 'lower', 'ltrim', 'nchar',
            'patindex', 'quotename', 'replace', 'replicate', 'reverse', 'right', 'rtrim', 'soundex', 'space', 'str', 'stuff',
            'substring', 'unicode', 'upper', 'current_timestamp', 'current_date', 'current_time', 'dateadd', 'datediff', 'datename',
            'datepart', 'day', 'getdate', 'getutcdate', 'isdate', 'month', 'sysdatetime', 'sysutcdatetime', 'year', 'convert',
            'cast', 'try_convert', 'try_cast', 'parse', 'try_parse', 'iif', 'choose', 'coalesce', 'nullif', 'isnull', 'isnumeric',
            'isjson', 'session_user', 'system_user', 'current_user', 'user_name', 'schema_name', 'database_name', 'object_name',
            'column_name', 'index_name', 'constraint_name', 'trigger_name', 'view_name', 'procedure_name', 'function_name',
            'parameter_name', 'type_name', 'assembly_name', 'file_name', 'login_name', 'server_name', 'service_name', 'queue_name',
            'contract_name', 'message_type_name', 'route_name', 'remote_service_name', 'fulltext_catalog_name', 'fulltext_stoplist_name',
            'search_property_list_name', 'certificate_name', 'symmetric_key_name', 'asymmetric_key_name', 'credential_name',
            'cryptographic_provider_name', 'audit_name', 'audit_specification_name', 'server_audit_specification_name',
            'database_audit_specification_name', 'endpoint_name', 'event_notification_name', 'linked_server_name', 'login_token',
            'master_key', 'password', 'principal', 'role', 'schema', 'sequence', 'server_role', 'service_broker', 'signature',
            'statistics', 'symmetric_key', 'synonym', 'user', 'workload_group', 'xml_schema_collection'
        ]
        
        keyword_pattern = re.compile(r'\b(' + '|'.join(sql_keywords) + r')\b', re.IGNORECASE)
        previous = girdi
        
        while True:
            temiz = re.sub(special_chars_pattern, '', previous)
            
            current = keyword_pattern.sub('', temiz)
            
            if current == previous:
                break
            
        previous = current
    
        return current

    elif mod == 3:
        escape_map = {
            "\\": "\\\\",
            "'": "\\'",
            "\"": "\\\"",
            ";": "\\;",
            "-": "\\-",
            "#": "\\#",
            "*": "\\*",
            "/": "\\/",
            "(": "\\(",
            ")": "\\)",
            "=": "\\=",
            "+": "\\+",
            "|": "\\|"
        }
        return ''.join(escape_map.get(c, c) for c in girdi)
        
    # hatali mod verilmesi durumunda mod 1'i kullan
    else:
        ozel_karakterler = r"[\'\";\\\-–—#/*()|=+]"
        return re.sub(ozel_karakterler, '', girdi)
