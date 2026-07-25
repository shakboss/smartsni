sudo systemctl restart sni                                                                                                        
journalctl -u sni -n 5 --no-pager                                                                                                                                          
curl -k https://home.shaktt.xyz/                                                                                                                                           
journalctl -u sni -n 10 --no-pager
